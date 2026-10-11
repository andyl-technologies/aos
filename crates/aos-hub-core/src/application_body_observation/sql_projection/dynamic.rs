//! Successful dynamic operation boundaries inside the optional request scope.
//!
//! Original documents and returned values use their real serializers. Only
//! commitments enter a checkpoint; credentials, SQL text and bound values do
//! not. A successful source boundary does not establish an independent SQL
//! snapshot, transport authentication or later publication visibility.

use super::{Checkpoint, EncodedImage, Selection, MAX_BYTES};
use crate::auth::jwt::Claims;
use crate::backend::CheckedStatement;
use crate::clock::{observation_unix_nanos, Instant};
use crate::db::{DirectUploadSessionRecord, RegistryPublicationRecord, RegistryRecord};
use crate::direct_upload::{
    DirectCompleteStep, DirectCompletionEvidence, DirectDestinationBaselinePermission,
    DirectFinalGuardRecord, DirectLogicalAction, DirectRequestContext, DirectSessionAuthorization,
    DirectSessionState, WireInteger,
};
use serde::{Serialize, Serializer};

const MAX_ORIGINAL_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(super) enum Observation {
    PublicationGet {
        publication_id: String,
        registry_id: String,
        ordinal: String,
        state: String,
        manifest_digest: String,
        refs_digest: String,
        registry_scope_sha256: String,
        actor: EncodedImage,
        reply: EncodedImage,
    },
    DirectAuthorize {
        session_id: String,
        request_context: EncodedImage,
        selected_original: EncodedImage,
        action: DirectLogicalAction,
        complete_step: Option<DirectCompleteStep>,
        admission: EncodedImage,
        returned_status: EncodedImage,
        baseline_permissions: EncodedImage,
        observed_state: DirectSessionState,
        observed_resource_version: WireInteger,
    },
    DirectCommit {
        session_id: String,
        deployment_sha256: String,
        admission: EncodedImage,
        complete_original: EncodedImage,
        completion_evidence: EncodedImage,
        final_guards: EncodedImage,
        expected_resource_version: WireInteger,
        resulting_resource_version: Option<WireInteger>,
        checked_statements: Option<EncodedImage>,
        checked_statement_count: usize,
        retained_original: bool,
    },
}

impl Observation {
    pub(super) fn constructor(&self) -> &'static str {
        match self {
            Self::PublicationGet { .. } => "publication_get",
            Self::DirectAuthorize { .. } | Self::DirectCommit { .. } => "direct_logical_validated",
        }
    }
}

/// Brackets the actual operation without changing its result or error path.
pub(crate) struct Started {
    before: u128,
    start: Instant,
}

impl Started {
    /// Begins a bracket only when the existing observation scope is enabled.
    pub(crate) fn new() -> Option<Self> {
        if !super::super::enabled() {
            return None;
        }

        let before = match observation_unix_nanos() {
            Some(before) => before,
            None => {
                super::super::invalidate_sql_projection();
                return None;
            }
        };

        Some(Self {
            before,
            start: Instant::now(),
        })
    }

    /// Retains an actually authorized Get and its completed response image.
    pub(crate) fn publication_get(
        self,
        claims: &Claims,
        publication: &RegistryPublicationRecord,
        registry: &RegistryRecord,
        reply: &aos_proto_types::RegistryPublication,
    ) {
        let observation = (|| {
            Some(Observation::PublicationGet {
                publication_id: publication.publication_id.clone(),
                registry_id: publication.registry_id.to_string(),
                ordinal: publication.ordinal.to_string(),
                state: publication.state.clone(),
                manifest_digest: publication.manifest_digest.clone(),
                refs_digest: publication.refs_digest.clone(),
                registry_scope_sha256: super::digest(&registry.scope_key),
                actor: image(&(
                    &claims.sub,
                    &claims.owner_kind,
                    claims.owner_id,
                    &claims.owner_incarnation,
                    &claims.scope,
                    &claims.perms,
                ))?,
                reply: image(reply)?,
            })
        })();
        self.completed(observation);
    }

    /// Retains a successful per-original Authorize result after its guards.
    pub(crate) fn direct_authorize(
        self,
        context: &DirectRequestContext,
        selected: &DirectSessionAuthorization,
        action: DirectLogicalAction,
        complete_step: Option<DirectCompleteStep>,
        record: &DirectUploadSessionRecord,
        permissions: &[DirectDestinationBaselinePermission],
    ) {
        let observation = (|| {
            Some(Observation::DirectAuthorize {
                session_id: record.admission.session_id.clone(),
                request_context: image(context)?,
                selected_original: image(selected)?,
                action,
                complete_step,
                admission: image(&record.admission)?,
                returned_status: image(&record.status(&context.deployment_id).ok()?)?,
                baseline_permissions: image(&permissions)?,
                observed_state: record.state,
                observed_resource_version: record.resource_version,
            })
        })();
        self.completed(observation);
    }

    /// Retains a successful checked Commit or an exact retained-original replay.
    pub(crate) fn direct_commit(
        self,
        deployment: &str,
        record: &DirectUploadSessionRecord,
        evidence: &DirectCompletionEvidence,
        guards: &[DirectFinalGuardRecord],
        statements: Option<&[CheckedStatement]>,
    ) {
        let observation = (|| {
            let complete = record.complete_intent.as_ref()?;
            let retained_original = statements.is_none();
            let resulting_resource_version = if retained_original {
                None
            } else {
                Some(WireInteger::new(
                    record.resource_version.get().checked_add(1)?,
                ))
            };
            Some(Observation::DirectCommit {
                session_id: record.admission.session_id.clone(),
                deployment_sha256: super::digest(deployment),
                admission: image(&record.admission)?,
                complete_original: image(complete)?,
                completion_evidence: image(evidence)?,
                final_guards: image(&guards)?,
                expected_resource_version: record.resource_version,
                resulting_resource_version,
                checked_statements: match statements {
                    Some(statements) => Some(image(&CheckedImages(statements))?),
                    None => None,
                },
                checked_statement_count: statements.map_or(0, <[CheckedStatement]>::len),
                retained_original,
            })
        })();
        self.completed(observation);
    }

    fn completed(self, observation: Option<Observation>) {
        let selection = observation.map(|observation| Selection::Dynamic { observation });
        let Some(selection) =
            selection.filter(|selection| super::super::canonical(selection, MAX_BYTES).is_some())
        else {
            super::super::invalidate_sql_projection();
            return;
        };
        let Some(after) = observation_unix_nanos().filter(|after| *after >= self.before) else {
            super::super::invalidate_sql_projection();
            return;
        };

        super::super::record_sql_checkpoint(Checkpoint {
            selection,
            source_before_unix_nanos: self.before.to_string(),
            source_after_unix_nanos: after.to_string(),
            source_elapsed_nanos: self.start.elapsed().as_nanos().to_string(),
        });
    }
}

fn image<T: Serialize>(value: &T) -> Option<EncodedImage> {
    super::super::canonical(value, MAX_ORIGINAL_BYTES)
}

struct CheckedImages<'a>(&'a [CheckedStatement]);

impl Serialize for CheckedImages<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|checked| {
            (
                &checked.statement.sql,
                &checked.statement.params,
                checked.expected_rows,
            )
        }))
    }
}
