//! Retains the shared historical namespace and capacity ownership admission.
//!
//! The same genuine Source pays these two complete canonical scans from the
//! already held prefix before either decoder can allocate. Native history and
//! current rows are compared by the ordinary namespace engine; no guard escapes.

use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityReadCaptureV1;

use super::*;
use crate::RecordNamespace;

#[derive(Debug, thiserror::Error)]
enum NamespaceDemandError {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

pub(super) struct MainNamespaceOriginalV1 {
    demand: Option<Result<ResourceVector, NamespaceDemandError>>,
    captures: [CanonicalCapacityReadCaptureV1; 2],
    result: Option<Result<(), JournalError>>,
    entered: bool,
}

impl MainNamespaceOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            demand: None,
            captures: std::array::from_fn(|_| CanonicalCapacityReadCaptureV1::new()),
            result: None,
            entered: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.demand
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

impl Method46InitialMainWriterOriginalV1 {
    fn namespace_demand(&self) -> Result<ResourceVector, NamespaceDemandError> {
        let extent = self
            .inner
            .captured_extent()
            .ok_or(JournalError::ProtectedBoundary)?;
        let invalid = || JournalError::JournalTooLarge;
        let rows = usize::try_from(extent.native_bytes)
            .map_err(|_| invalid())?
            .checked_div(aos_sandbox_journal::framing::HEADER_BYTES)
            .ok_or_else(invalid)?
            .min(extent.limits.maximum_materialized_records);
        let (bytes, cells) =
            CanonicalCapacityReadCaptureV1::receiving_obligations_v1(rows).ok_or_else(invalid)?;
        let names =
            CanonicalCapacityReadCaptureV1::receiving_named_entries_v2(rows).ok_or_else(invalid)?;
        let backing = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(
                D::MetadataEntries,
                u64::try_from(cells.checked_add(names).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?,
            );

        // Each retained scan also receives a full independent semantic-prefix
        // allowance for nested canonical provenance scratch. Existing replay
        // payment and future positive disposal supply no credit here.
        let scan = extent
            .dominant_semantic_receiving_demand_v1()?
            .checked_add(backing)?;
        Ok(scan.checked_add(scan)?)
    }

    pub(crate) fn quote_namespace_once(&mut self) -> Option<ResourceVector> {
        if self.namespace.demand.is_some()
            || self.namespace.entered
            || self.post.is_some()
            || self.failure().is_some()
            || self.nonempty.is_some()
            || self.inner.captured_extent().is_none()
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.namespace.demand = Some(self.namespace_demand());
        self.namespace.demand.as_ref()?.as_ref().ok().copied()
    }

    pub(crate) fn admit_namespace_once(&mut self) -> Result<(), JournalError> {
        if self.namespace.entered
            || self.post.is_some()
            || self.failure().is_some()
            || !matches!(self.namespace.demand, Some(Ok(_)))
            || !matches!(self.nonempty, Some(Ok(())))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.namespace.entered = true;
        self.namespace.result = Some((|| {
            let journal = self
                .inner
                .original
                .journal_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?;
            journal.require_protected_namespace_engine_v1(
                RecordNamespace::BrokerSessionTraffic,
                Some(&mut self.namespace.captures),
            )
        })());
        if self.namespace_admitted() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn namespace_admitted(&self) -> bool {
        self.namespace.entered && matches!(self.namespace.result, Some(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
use crate::RecordNamespace;

    #[test]
    fn method46_initial_namespace_scan_requires_actual_prepared_prefix() {
        let mut original = Method46InitialMainWriterOriginalV1::new();

        assert!(original.quote_namespace_once().is_none());
        assert!(original.admit_namespace_once().is_err());

        assert!(!original.namespace.entered);
        assert!(original.namespace.demand.is_none());
        assert!(original.namespace.result.is_none());
        assert!(original.namespace.captures.iter().all(|capture| {
            capture.retained_families_v1().is_empty() && capture.retained_identity_count_v1() == 0
        }));
        assert!(!original.readback_available_data());
    }
}
