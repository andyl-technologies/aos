//! Held controller/source-domain/Cache/root cut for a closed policy binding.
//!
//! A future controller caller supplies its already-held controller journal.
//! This bridge opens source-domain and protected Cache custody in that order,
//! then acquires the root writer through the authenticated local exchange.
//! The bridge durably freezes Controller and source-domain mutations before Q04 SUBMIT;
//! root retains its writer through AOSPCB02 CAS and terminal acknowledgement.
//! Cache still has only process-local custody and rechecks. A crash leaves
//! Controller and source-domain journals frozen for exact root cold readback,
//! whether root committed or not. No production Create path calls this bridge,
//! and its observation cannot authorize policy publication or an effect.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::cache_residency::CacheResidencyProtectedOwnerV1;
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    ClosedPolicyRootCasBaseV2, PolicyCompilerInputV1, closed_policy_binding_digest_v2,
    current_parentless_create_project_source_v1,
    propose_closed_current_create_explicit_policy_binding_v2,
    with_current_create_policy_source_barrier_v4,
};
use aos_sandbox::{ControllerPolicyHoldV1, Journal, journal::SourceDomainPolicyHoldV1};
use aos_sandbox_core::{OperationId, SandboxId};
use ed25519_dalek::VerifyingKey;

use crate::policy_authority_client::{
    ClosedPolicyBindingClientObservationV4, commit_closed_policy_binding_v4,
};

/// Opens and retains all remaining owners under the held controller writer.
///
/// The caller must supply a protected, writer-held controller journal and its
/// privileged controller UID, not values from a public request. The accepted
/// Create is checked before source-domain and Cache open, which fixes local
/// lock order. The verification keys only check the root receipt; privileged
/// root deployment credentials choose the authoritative signer generations.
/// A successful return reports an inert durable root record and leaves both
/// source journals frozen until root-only cold resolution. It is not permission
/// to publish or hand off an effect.
///
/// # Errors
///
/// Rejects stale Create, ancestry, publisher, revocation, or protected Cache
/// state, changed signed inputs, root peer or CAS mismatch, and lost transport.
#[allow(clippy::too_many_arguments)]
pub fn commit_fixed_parentless_create_closed_binding_v4(
    controller: &mut Journal,
    controller_uid: u32,
    operation: OperationId,
    sandbox: SandboxId,
    input: &PolicyCompilerInputV1,
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
) -> io::Result<ClosedPolicyBindingClientObservationV4> {
    current_parentless_create_project_source_v1(controller, operation, sandbox)
        .map_err(io::Error::other)?;
    let (mut source_domains, _) =
        ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(controller_uid)
            .map_err(io::Error::other)?;
    let (mut cache, _) =
        CacheResidencyProtectedOwnerV1::open_fixed_protected_for_uid(controller_uid)
            .map_err(io::Error::other)?;

    commit_under_held_owners(
        controller,
        &mut source_domains,
        &mut cache,
        operation,
        sandbox,
        input,
        deployment_verifying_key,
        project_verifying_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_under_held_owners(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    input: &PolicyCompilerInputV1,
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
) -> io::Result<ClosedPolicyBindingClientObservationV4> {
    with_current_create_policy_source_barrier_v4(
        controller,
        source_domains,
        cache,
        operation,
        sandbox,
        |controller, source_domains, source, heads| {
            commit_closed_policy_binding_v4(
                deployment_verifying_key,
                project_verifying_key,
                |receipt, remote_base| {
                    if !receipt.matches_compiler_input(source, input) {
                        return Err(invalid_cut());
                    }
                    let root_base = ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields(
                        remote_base.issuer_owner(),
                        remote_base.predecessor(),
                        remote_base.next_generation(),
                        remote_base.deployment_signer_generation(),
                        remote_base.project_signer_generation(),
                    )
                    .map_err(io::Error::other)?;
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(io::Error::other)?;
                    let now = i64::try_from(now.as_secs()).map_err(io::Error::other)?;
                    let proposed = propose_closed_current_create_explicit_policy_binding_v2(
                        source,
                        heads,
                        receipt.project(),
                        receipt.head(),
                        receipt.sources(),
                        input,
                        root_base,
                        now,
                    )
                    .map_err(io::Error::other)?;
                    let binding =
                        closed_policy_binding_digest_v2(&proposed).map_err(io::Error::other)?;
                    let hold = ControllerPolicyHoldV1::new(
                        operation,
                        sandbox,
                        source.commitment(),
                        binding,
                        remote_base.next_generation(),
                    )
                    .map_err(io::Error::other)?;
                    controller
                        .acquire_controller_policy_hold_v1(hold)
                        .map_err(io::Error::other)?;
                    let source_hold = SourceDomainPolicyHoldV1::new(
                        operation,
                        sandbox,
                        source.commitment(),
                        heads.ancestry(),
                        binding,
                        remote_base.next_generation(),
                    )
                    .map_err(io::Error::other)?;
                    source_domains
                        .acquire_closed_policy_source_hold_v1(source_hold)
                        .map_err(io::Error::other)?;
                    Ok(proposed)
                },
            )
        },
    )
    .map_err(io::Error::other)?
}

fn invalid_cut() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "policy owner cut changed")
}
