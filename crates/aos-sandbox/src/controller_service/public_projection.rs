//! Authorized native journal queries over canonical public projections.
//!
//! Protocol owns the projection DATA and codec reexported here. This owner keeps
//! bounded native query selection, project authorization, and borrowed Journal
//! access. A checked projection does not establish observed-success evidence;
//! authoritative broker receipts and inventory supply that evidence.

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};

use crate::cli_model::AuditAuthorizationV1;
use crate::{Journal, RecordNamespace};

use aos_sandbox_protocol::public_api::projection::{
    PROJECTION_KEY_PREFIX, decode_checked_public_projection_v1 as decode_record,
    projection_kind_prefix, select_parentless_create_sandbox,
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
        let kind_prefix = projection_kind_prefix(kind);
        let mut records = Vec::new();
        for (key, value) in self.journal.records(RecordNamespace::DesiredState) {
            if key.starts_with(&kind_prefix) {
                let record = decode_record(key, value)?;
                if record.project() == project {
                    records.push(record);
                }
            }
        }
        Ok(records)
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
        for (key, value) in self.journal.records(RecordNamespace::DesiredState) {
            if key.starts_with(PROJECTION_KEY_PREFIX) {
                let record = decode_record(key, value)?;
                if record.operation() == operation {
                    records.push(record);
                }
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
