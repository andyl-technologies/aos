//! Retains a Controller-adopted request beside its sealed mutation authority.
//!
//! Only the existing authenticated mutation path constructs this envelope.
//! Public proposals and opaque client context live below this owner in protocol;
//! they cannot be converted into adopted provenance by this module's public API.

use aos_proto::aos::sandbox::v1 as wire;
use aos_sandbox_protocol::public_api::proto_json::StructuredOutputSchemaV1;
use aos_sandbox_protocol::public_api::request::{
    DormantClientStatePlanV1, DormantSandboxOutputV1, DormantSandboxRequestKindV1,
    DormantSandboxRoutingErrorV1, PublicSandboxRequestDataV1,
};

use super::provenance::AuthorizedResolvedMutationV1;
use super::requests::{ResolvedLifecycleActionV1, ResolvedPublicMutationProtoV1};

/// Retains structurally checked request DATA with exact adopted mutation authority.
#[derive(Clone, Debug, PartialEq)]
pub struct DormantSandboxRequestV1 {
    data: PublicSandboxRequestDataV1,
    authorization: AuthorizedResolvedMutationV1,
}

impl DormantSandboxRequestV1 {
    /// Constructs an effect route only from exact authenticated mutation authority.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] if the resolved
    /// protobuf projection or renderer/client plan is inconsistent.
    pub(crate) fn from_authorized_mutation(
        authorized: AuthorizedResolvedMutationV1,
        output: DormantSandboxOutputV1,
        client_state: DormantClientStatePlanV1,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        let kind = match authorized.mutation().to_proto() {
            ResolvedPublicMutationProtoV1::CreateSandbox(v) => {
                DormantSandboxRequestKindV1::Create(v)
            }
            ResolvedPublicMutationProtoV1::UpdatePolicy(v) => {
                DormantSandboxRequestKindV1::UpdatePolicy(v)
            }
            ResolvedPublicMutationProtoV1::Lifecycle { action, request } => match action {
                ResolvedLifecycleActionV1::Start
                | ResolvedLifecycleActionV1::ReconstructHibernated => {
                    DormantSandboxRequestKindV1::Start(request)
                }
                ResolvedLifecycleActionV1::Stop => DormantSandboxRequestKindV1::Stop(request),
                ResolvedLifecycleActionV1::Suspend => DormantSandboxRequestKindV1::Suspend(request),
                ResolvedLifecycleActionV1::ResumeFrozen => {
                    DormantSandboxRequestKindV1::Resume(request)
                }
            },
            ResolvedPublicMutationProtoV1::DeleteSandbox(v) => {
                DormantSandboxRequestKindV1::Delete(v)
            }
            ResolvedPublicMutationProtoV1::CreateExecution(v) => {
                DormantSandboxRequestKindV1::Exec(v)
            }
            ResolvedPublicMutationProtoV1::ExecutionControl(v) => {
                DormantSandboxRequestKindV1::ExecutionControl(v)
            }
            ResolvedPublicMutationProtoV1::CancelExecution(v) => {
                DormantSandboxRequestKindV1::CancelExec(v)
            }
            ResolvedPublicMutationProtoV1::CancelOperation(v) => {
                DormantSandboxRequestKindV1::CancelOperation(v)
            }
            ResolvedPublicMutationProtoV1::CreateView(v) => {
                DormantSandboxRequestKindV1::ViewCreate(v)
            }
            ResolvedPublicMutationProtoV1::AttachView(v) => {
                DormantSandboxRequestKindV1::ViewAttach(v)
            }
            ResolvedPublicMutationProtoV1::ReplaceAttachment(v) => {
                DormantSandboxRequestKindV1::ViewReplace(v)
            }
            ResolvedPublicMutationProtoV1::DetachView(v) => {
                DormantSandboxRequestKindV1::ViewDetach(v)
            }
            ResolvedPublicMutationProtoV1::ReleaseView(v) => {
                DormantSandboxRequestKindV1::ViewRelease(v)
            }
            ResolvedPublicMutationProtoV1::CreateSnapshot(v) => {
                DormantSandboxRequestKindV1::Snapshot(v)
            }
            ResolvedPublicMutationProtoV1::RestoreSnapshot(v) => {
                DormantSandboxRequestKindV1::Restore(v)
            }
            ResolvedPublicMutationProtoV1::DeleteSnapshot(v) => {
                DormantSandboxRequestKindV1::DeleteSnapshot(v)
            }
            ResolvedPublicMutationProtoV1::ForkSnapshot(v) => DormantSandboxRequestKindV1::Fork(v),
            ResolvedPublicMutationProtoV1::CachePin(v) => DormantSandboxRequestKindV1::CachePin(v),
            ResolvedPublicMutationProtoV1::CacheUnpin(v) => {
                DormantSandboxRequestKindV1::CacheUnpin(v)
            }
            ResolvedPublicMutationProtoV1::Capability(value) => match value {
                super::requests::ResolvedCapabilityProtoV1::Attenuate(v) => {
                    DormantSandboxRequestKindV1::CapabilityAttenuate(v)
                }
                super::requests::ResolvedCapabilityProtoV1::Inspect(v) => {
                    DormantSandboxRequestKindV1::CapabilityInspect(v)
                }
                super::requests::ResolvedCapabilityProtoV1::Renew(v) => {
                    DormantSandboxRequestKindV1::CapabilityRenew(v)
                }
                super::requests::ResolvedCapabilityProtoV1::Revoke(v) => {
                    DormantSandboxRequestKindV1::CapabilityRevoke(v)
                }
            },
        };
        let data = PublicSandboxRequestDataV1::new(kind, output, client_state)?;
        Ok(Self {
            data,
            authorization: authorized,
        })
    }

    /// Returns the exact typed request variant.
    #[must_use]
    pub const fn kind(&self) -> &DormantSandboxRequestKindV1 {
        self.data.kind()
    }

    /// Returns the method-preserving protobuf oneof for transport handoff.
    #[must_use]
    pub const fn command(&self) -> Option<&wire::SandboxCommandRequest> {
        self.data.command()
    }

    /// Returns retained authority only to an in-crate effect transport.
    #[must_use]
    pub(crate) const fn authorization(&self) -> Option<&AuthorizedResolvedMutationV1> {
        Some(&self.authorization)
    }

    /// Returns stable output framing.
    #[must_use]
    pub const fn output(&self) -> DormantSandboxOutputV1 {
        self.data.output()
    }

    /// Returns the checked local-state and polling bounds.
    #[must_use]
    pub const fn client_state(&self) -> DormantClientStatePlanV1 {
        self.data.client_state()
    }

    /// Returns the exact renderer schema after applying wait-vs-operation policy.
    #[must_use]
    pub const fn response_schema(&self) -> StructuredOutputSchemaV1 {
        self.data.response_schema()
    }

    /// Validates the canonical structural request DATA without granting authority.
    ///
    /// # Errors
    ///
    /// Returns the established routing error when a request invariant is invalid.
    pub fn validate(&self) -> Result<(), DormantSandboxRoutingErrorV1> {
        self.data.validate()
    }
}
