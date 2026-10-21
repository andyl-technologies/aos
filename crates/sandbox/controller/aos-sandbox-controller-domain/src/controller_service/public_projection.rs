//! Authorized native journal queries over canonical public projections.
//!
//! Protocol owns projection DATA and codecs; callers import them directly.
//! This owner keeps bounded native queries, authorized read carriers and
//! Journal borrows. Observed-success evidence comes from authoritative broker
//! receipts and inventory.

use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, SandboxId};

use crate::cli_model::AuditAuthorizationV1;
use crate::{Journal, RecordNamespace};

use aos_sandbox_protocol::public_api::projection::{
    PROJECTION_KEY_PREFIX, decode_checked_public_projection_v1 as decode_record,
    select_parentless_create_sandbox,
};
use aos_sandbox_protocol::public_api::projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionRecordV1, projection_key,
};

/// Selects one bounded public projection read inside the controller worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicProjectionQueryV1 {
    /// Loads one exact resource identity.
    One {
        /// Selects the closed resource schema.
        kind: PublicProjectionKindV1,
        /// Names the exact stable resource.
        resource_id: [u8; 16],
    },
    /// Lists one resource schema within an authenticated project.
    List {
        /// Selects the closed resource schema.
        kind: PublicProjectionKindV1,
        /// Selects the exact project partition.
        project: ProjectId,
    },
    /// Resolves a scope resource and lists another kind in the same project.
    Related {
        /// Selects the returned resource schema.
        kind: PublicProjectionKindV1,
        /// Selects the resource whose project defines the partition.
        scope_kind: PublicProjectionKindV1,
        /// Names the exact scope resource.
        scope_id: [u8; 16],
    },
}

/// Carries authorization and checked rows from one worker-owned read.
#[must_use = "an authorized public projection read must be returned or deliberately discarded"]
pub struct AuthorizedPublicProjectionReadV1 {
    authorization: AuditAuthorizationV1,
    records: Vec<PublicProjectionRecordV1>,
}

impl AuthorizedPublicProjectionReadV1 {
    pub(crate) fn new(
        authorization: AuditAuthorizationV1,
        records: Vec<PublicProjectionRecordV1>,
    ) -> Self {
        Self {
            authorization,
            records,
        }
    }

    /// Consumes the read into its current authorization and checked rows.
    #[must_use]
    pub fn into_parts(self) -> (AuditAuthorizationV1, Vec<PublicProjectionRecordV1>) {
        (self.authorization, self.records)
    }
}

/// Reads checked public projections from the sole controller journal.
pub struct PublicProjectionStoreV1<'journal> {
    journal: &'journal Journal,
}

impl<'journal> PublicProjectionStoreV1<'journal> {
    /// Borrows the journal without creating another owner or materialized index.
    #[must_use]
    pub const fn new(journal: &'journal Journal) -> Self {
        Self { journal }
    }

    /// Loads one exact projection.
    ///
    /// # Errors
    ///
    /// Returns [`PublicProjectionError`] when a retained record is malformed,
    /// noncanonical, mismatched, or fails the public resource validator.
    pub fn get(
        &self,
        kind: PublicProjectionKindV1,
        resource_id: [u8; 16],
    ) -> Result<Option<PublicProjectionRecordV1>, PublicProjectionError> {
        aos_sandbox_protocol::checked_public_projection_read_data_v1!(
            kind = kind, resource_id = resource_id,
            invalid_identity = PublicProjectionError::InvalidIdentity,
            healthy = { self.journal.ensure_healthy().map_err(|_| PublicProjectionError::CorruptRecord)?; },
            key = key, read = self.journal.get(RecordNamespace::DesiredState, &key), output = projection
        );
        Ok(projection)
    }

    /// Lists one kind and project in stable resource-identity order.
    ///
    /// # Errors
    ///
    /// Returns [`PublicProjectionError`] when any record under the reserved
    /// prefix is malformed, including a record outside the requested project.
    pub fn list(
        &self,
        kind: PublicProjectionKindV1,
        project: ProjectId,
    ) -> Result<Vec<PublicProjectionRecordV1>, PublicProjectionError> {
        if project.as_bytes() == &[0; 16] {
            return Err(PublicProjectionError::InvalidIdentity);
        }
        let mut records = Vec::new();
        for record in self.iter_kind_v2(kind)? {
            let record = record?;
            if record.project() == project {
                records.push(record);
            }
        }
        Ok(records)
    }

    // The same complete reserved-prefix decoder serves ordinary listing and
    // genuine paid internal graph consumers. This iterator grants no read or
    // native currentness; its caller must already hold that actual interval.
    pub(crate) fn iter_kind_v2(&self, kind: PublicProjectionKindV1)
        -> Result<impl Iterator<Item = Result<PublicProjectionRecordV1, PublicProjectionError>> + '_, PublicProjectionError>
    {
        self.iter_rows_v2(Some(kind))
    }

    pub(crate) fn iter_all_v2(&self)
        -> Result<impl Iterator<Item = Result<PublicProjectionRecordV1, PublicProjectionError>> + '_, PublicProjectionError>
    {
        self.iter_rows_v2(None)
    }

    fn iter_rows_v2(&self, kind: Option<PublicProjectionKindV1>)
        -> Result<impl Iterator<Item = Result<PublicProjectionRecordV1, PublicProjectionError>> + '_, PublicProjectionError>
    {
        self.journal.ensure_healthy().map_err(|_| PublicProjectionError::CorruptRecord)?;
        Ok(aos_sandbox_protocol::public_api::projection::iter_public_projection_rows_data_v2(
            self.journal.records(RecordNamespace::DesiredState), kind))
    }

    /// Lists every projection atomically linked to one admitted operation.
    ///
    /// # Errors
    ///
    /// Returns [`PublicProjectionError`] when any retained projection is
    /// malformed or the operation identity is zero.
    pub fn list_operation(
        &self,
        operation: OperationId,
    ) -> Result<Vec<PublicProjectionRecordV1>, PublicProjectionError> {
        aos_sandbox_protocol::checked_public_projection_list_operation_data_v2!(
            operation = operation, invalid_identity = PublicProjectionError::InvalidIdentity,
            healthy = { self.journal.ensure_healthy().map_err(|_| PublicProjectionError::CorruptRecord)?; },
            rows = self.journal.records(RecordNamespace::DesiredState), output = records
        );
        Ok(records)
    }

    /// Selects the sole parentless Sandbox projection accepted with a Create.
    ///
    /// This is only a durable identity selector. The policy source, publisher,
    /// ancestry, and physical Cache still require independent currentness joins.
    ///
    /// # Errors
    ///
    /// Rejects malformed retained projections or a zero operation identity.
    pub fn one_parentless_create_sandbox(
        &self,
        operation: OperationId,
        project: ProjectId,
    ) -> Result<Option<(SandboxId, ObjectDigest)>, PublicProjectionError> {
        let records = self.list_operation(operation)?;
        Ok(select_parentless_create_sandbox(
            &records, operation, project,
        ))
    }
}

pub(crate) use aos_sandbox_protocol::public_api::projection::geometry::
    sandbox_projection_decoding_receiving_bytes_v2;

/// Reads one projection while retaining the actual Journal or Root model owner.
///
/// This private entry shares the public Store recipe without changing the
/// Store's existing layout or accepting a supplied map as a native original.
/// Identity, actual owner health, key allocation and decode remain ordered.
pub(crate) fn get_from_observation_v2(
    original: crate::journal::historical_observation::HistoricalObservationV1<'_>,
    kind: PublicProjectionKindV1,
    resource_id: [u8; 16],
) -> Result<Option<PublicProjectionRecordV1>, PublicProjectionError> {
    aos_sandbox_protocol::checked_public_projection_read_data_v1!(
        kind = kind, resource_id = resource_id,
        invalid_identity = PublicProjectionError::InvalidIdentity,
        healthy = { original.ensure_healthy().map_err(|_| PublicProjectionError::CorruptRecord)?; },
        key = key, read = original.get(RecordNamespace::DesiredState, &key), output = projection
    );
    Ok(projection)
}

/// Lists operation projections through the same genuine owner and decoder.
///
/// The original empty-Vec, health check, full-prefix decode, filter and sort
/// chronology is shared lexically with the public Store method.
pub(crate) fn list_operation_from_observation_v2(
    original: crate::journal::historical_observation::HistoricalObservationV1<'_>,
    operation: OperationId,
) -> Result<Vec<PublicProjectionRecordV1>, PublicProjectionError> {
    aos_sandbox_protocol::checked_public_projection_list_operation_data_v2!(
        operation = operation, invalid_identity = PublicProjectionError::InvalidIdentity,
        healthy = { original.ensure_healthy().map_err(|_| PublicProjectionError::CorruptRecord)?; },
        rows = original.records(RecordNamespace::DesiredState), output = records
    );
    Ok(records)
}

/// Prices the reached genuine-owner projection entry's typed forwarding peak.
pub(crate) fn projection_observation_control_bytes_v2() -> Option<usize> {
    use crate::journal::historical_observation::HistoricalObservationV1;
    use std::mem::size_of;

    let get = size_of::<(HistoricalObservationV1<'_>, PublicProjectionKindV1, [u8; 16])>()
        .checked_mul(3)?
        .checked_add(size_of::<Result<Option<PublicProjectionRecordV1>, PublicProjectionError>>().checked_mul(3)?)?;
    let list = size_of::<(HistoricalObservationV1<'_>, OperationId)>().checked_mul(3)?
        .checked_add(size_of::<Result<Vec<PublicProjectionRecordV1>, PublicProjectionError>>().checked_mul(3)?)?;
    get.max(list)
        .checked_add(size_of::<Result<(), crate::JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
