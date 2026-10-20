//! Authorized native journal queries over canonical public projections.
//!
//! Protocol owns projection DATA and codecs; callers import them directly.
//! This owner keeps bounded native queries, authorized read carriers and
//! Journal borrows. Observed-success evidence comes from authoritative broker
//! receipts and inventory.

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};

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
        if resource_id == [0; 16] {
            return Err(PublicProjectionError::InvalidIdentity);
        }
        self.journal.ensure_healthy().map_err(|_| PublicProjectionError::CorruptRecord)?;
        let key = projection_key(kind, resource_id);
        self.journal
            .get(RecordNamespace::DesiredState, &key)
            .map(|value| decode_record(&key, value))
            .transpose()
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
        if operation.as_bytes() == &[0; 16] {
            return Err(PublicProjectionError::InvalidIdentity);
        }
        let mut records = Vec::new();
        for record in self.iter_all_v2()? {
            let record = record?;
            if record.operation() == operation {
                records.push(record);
            }
        }
        records.sort_by(|left, right| {
            left.resource()
                .kind()
                .cmp(&right.resource().kind())
                .then_with(|| {
                    left.resource()
                        .resource_id()
                        .cmp(right.resource().resource_id())
                })
        });
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

// The execution source reads its current Execution projection through this
// same existing codec. The maximum includes every held projection with this prefix.
pub(crate) fn execution_source_receiving_bytes_v1(journal: &Journal) -> Option<u64> {
    projection_model_receiving_bytes_v1(journal,
        std::mem::size_of::<aos_proto::aos::sandbox::v1::Execution>())
}

// Root's preterminal comparison uses the same codec with its actual Sandbox
// model width. These bytes convey neither public success nor native custody.
pub(crate) fn sandbox_source_receiving_bytes_v1(journal: &Journal) -> Option<u64> {
    projection_model_receiving_bytes_v1(journal,
        std::mem::size_of::<aos_proto::aos::sandbox::v1::Sandbox>())
}

pub(crate) fn metadata_source_receiving_bytes_v2(journal: &Journal) -> Option<u64> {
    projection_model_receiving_bytes_v1(journal,
        std::mem::size_of::<aos_proto::aos::sandbox::v1::Snapshot>()
            .max(std::mem::size_of::<aos_proto::aos::sandbox::v1::FilesystemView>()))?
        .checked_add(u64::try_from(std::mem::size_of::<PublicProjectionRecordV1>()
            .checked_mul(3)?).ok()?)?
        .checked_add(u64::try_from(PROJECTION_KEY_PREFIX.len().checked_add(1 + 16)?
            .checked_mul(3)?).ok()?)
}

fn projection_model_receiving_bytes_v1(journal: &Journal, width: usize) -> Option<u64> {
    let mut maximum = 0usize;
    for (key, value) in journal.records(RecordNamespace::DesiredState) {
        if key.starts_with(PROJECTION_KEY_PREFIX) { maximum = maximum.max(value.len()); }
    }
    projection_encoded_model_receiving_bytes_v2(maximum, width)
}

// Historical native COMMIT comparison uses this SAME exact Sandbox decoder
// recipe with the actual maximum observed historical row, rather than a later
// possibly smaller current projection. The scalar supplies accounting DATA.
pub(crate) fn sandbox_projection_decoding_receiving_bytes_v2(encoded_bytes: usize) -> Option<u64> {
    projection_encoded_model_receiving_bytes_v2(encoded_bytes,
        std::mem::size_of::<aos_proto::aos::sandbox::v1::Sandbox>())
}

fn projection_encoded_model_receiving_bytes_v2(encoded_bytes: usize, width: usize) -> Option<u64> {
    let bytes = aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1(
        u64::try_from(encoded_bytes).ok()?, u64::try_from(width).ok()?,
    ).ok()?;
    // accepted_target and the spec producer each own their projected model;
    // its canonical round trip and command clone can coexist with that input.
    bytes.checked_mul(4)
}
