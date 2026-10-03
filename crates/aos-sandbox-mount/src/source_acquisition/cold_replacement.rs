//! Fresh-cold kind5 coordination and trusted local index installation.
//!
//! Only the Broker's absent-runtime entry constructs this owner. The installer
//! changes table DATA and four derived indexes; it never resets or fabricates
//! opaque custody. Hot abandonment and live-index reconciliation remain closed.

use aos_sandbox_protocol::mount_source_acquisition_state::{
    MountSourceAcquisitionStateV2, ProviderAttemptStateV2, StoredRecordV2,
};

use super::format::{materialized_record, provider_session_key, state_error};
use super::security::session_from_projection;
use super::transition::prepare_mutation;
use super::{
    FixedMountSourceAcquisitionOwnerV2, RecoveryMetadata, SourceAcquisitionRuntimeV2,
    SourceAcquisitionTableV2,
};
use crate::Result;

pub(super) fn install_and_retire_kind5_runtime(
    runtime: &mut SourceAcquisitionRuntimeV2,
    writer: &mut aos_sandbox::MountDeadReplacementJournalAuthorityV4<'_>,
    mut initial: Option<aos_sandbox::Kind5ProtectedReadbackV4>,
) -> Result<()> {
    let table = SourceAcquisitionTableV2::from_state(writer.current_source_state()?);
    let metadata = RecoveryMetadata::derive(&table)?;
    runtime.table = table;
    runtime.cold_pending_attempts = metadata.cold_pending_attempts;
    runtime.cold_released_rows = metadata.cold_released_rows;
    runtime.pending_backend_recovery_replacement = metadata.pending_backend_recovery_replacement;
    runtime.pending_inventory_recovery_replacement =
        metadata.pending_inventory_recovery_replacement;

    loop {
        require_installed_runtime(runtime, &writer.current_source_state()?)?;
        let readback = match initial.take() {
            Some(readback) => Some(readback),
            None => writer.pending_local_readbacks()?.into_iter().next(),
        };
        let Some(readback) = readback else {
            return Ok(());
        };
        writer.settle_kind5_local_readback(readback)?;
        // A DELETE advances the physical sequence. Rejoin each subsequent
        // token, and compare all installed indexes again before retiring it.
    }
}

fn require_installed_runtime(
    runtime: &SourceAcquisitionRuntimeV2,
    state: &MountSourceAcquisitionStateV2,
) -> Result<()> {
    if !runtime.table.matches_state(state) {
        return Err(state_error(
            "kind5 installed table differs from protected graph",
        ));
    }
    let metadata = RecoveryMetadata::derive(&runtime.table)?;
    if runtime.cold_pending_attempts != metadata.cold_pending_attempts
        || runtime.cold_released_rows != metadata.cold_released_rows
        || runtime.pending_backend_recovery_replacement
            != metadata.pending_backend_recovery_replacement
        || runtime.pending_inventory_recovery_replacement
            != metadata.pending_inventory_recovery_replacement
    {
        return Err(state_error(
            "kind5 installed recovery indexes differ from protected graph",
        ));
    }
    Ok(())
}

impl FixedMountSourceAcquisitionOwnerV2<'_> {
    /// Selects startup from the protected graph under the absent-runtime guard.
    pub(crate) fn establish_cold_dead_successor_v4(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        self.require_no_original_native_flight()?;
        let mut writer = self
            .protected
            .root_dead_replacement_authority_v4()
            .map_err(|error| state_error(&error.to_string()))?;
        let runtime = &mut self.runtime;
        require_installed_runtime(runtime, &writer.current_source_state()?)?;
        if runtime
            .table
            .provider_heads
            .values()
            .all(|head| head.pending_attempt.is_none() && head.recovery_barrier.is_none())
        {
            // Empty and simple-idle startup use the existing owner route. Only
            // the derivative borrow ends; the same journal and runtime remain.
            drop(writer);
            return self.establish_startup_provider_successor_v2(root);
        }

        let mut heads = runtime.table.provider_heads.values();
        let head = heads
            .next()
            .cloned()
            .ok_or_else(|| state_error("kind5 Head is absent"))?;
        if heads.next().is_some() {
            return Err(state_error("kind5 cold replacement has multiple scopes"));
        }
        let predecessor = runtime
            .table
            .provider_sessions
            .get(&head.current_session_id)
            .filter(|value| value.record_digest == head.current_session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("kind5 predecessor Session is absent"))?;

        if head.pending_attempt.is_none() {
            if head.recovery_barrier.is_none() {
                return Err(state_error("kind5 cold replay has no recovery barrier"));
            }
            let already_current = root
                .with_current_session(|session| -> Result<bool> {
                    let current = session
                        .current_session_id_v2()
                        .map_err(|_| state_error("kind5 replay Session custody is stale"))?;
                    if current.as_bytes() != &predecessor.session_binding {
                        return Ok(false);
                    }
                    require_installed_runtime(runtime, &writer.current_source_state()?)?;
                    if session
                        .current_session_id_v2()
                        .map_err(|_| state_error("kind5 replay final Session custody is stale"))?
                        .as_bytes()
                        != &predecessor.session_binding
                    {
                        return Err(state_error("kind5 replay final Session binding changed"));
                    }
                    Ok(true)
                })
                .map_err(|_| state_error("kind5 replay Root custody is stale"))?
                .ok_or_else(|| state_error("kind5 replay Root handshake is pending"))??;
            if already_current {
                return Ok(());
            }
            // The old local floor is already installed/retired. A different
            // actual Session needs the existing real kind2 plan, not a fabricated
            // pending Attempt or a changed-Session no-op. Its narrow root/tail
            // guards still refuse unsupported repeated/Release idle shapes.
            drop(writer);
            self.establish_startup_provider_successor_v2(root)?;
            let writer = self
                .protected
                .root_dead_replacement_authority_v4()
                .map_err(|error| state_error(&error.to_string()))?;
            return require_installed_runtime(&self.runtime, &writer.current_source_state()?);
        }

        root.with_current_session(|session| {
            let pending = head
                .pending_attempt
                .ok_or_else(|| state_error("kind5 has no pending Attempt"))?;
            let guard = writer.security_view();
            let death = session
                .try_prove_mount_provider_execution_dead_v2(
                    guard,
                    &guard.snapshot()?,
                    &provider_session_key(predecessor.session_id),
                    &materialized_record(StoredRecordV2::ProviderSession {
                        value: predecessor.clone(),
                    })?,
                )
                .map_err(|_| state_error("kind5 predecessor liveness is indeterminate"))?
                .ok_or_else(|| state_error("kind5 predecessor is not proven dead"))?;
            let (plan, identity, records) = runtime.table.prepare_dead_replacement_v4(
                guard,
                session,
                death,
                head.scope.holder_authority_id,
                head.scope.provider_authority_id,
            )?;
            let Some(StoredRecordV2::ProviderSession { value: successor }) = records.get(1) else {
                return Err(state_error("kind5 proposal lacks successor Session"));
            };
            let successor = successor.clone();
            let Some(StoredRecordV2::ProviderQueryAttempt { value: attempt }) = records.first()
            else {
                return Err(state_error("kind5 proposal lacks abandoned Attempt"));
            };
            if attempt.attempt_id != pending.id {
                return Err(state_error(
                    "kind5 proposal changed the selected pending Attempt",
                ));
            }
            let ProviderAttemptStateV2::AbandonedIndeterminate { dead_execution, .. } =
                &attempt.state
            else {
                return Err(state_error("kind5 proposal is not abandoned"));
            };
            let death = dead_execution.clone();
            let (_, expected) = prepare_mutation(&runtime.table, identity, records)?;
            let readback = session
                .with_dead_replacement_v4(&mut writer, plan, |projection, writer| {
                    let actual = session_from_projection(projection, Some(predecessor.session_id))?;
                    if actual != successor {
                        return Err(state_error(
                            "kind5 actual current plan differs from successor proposal",
                        ));
                    }
                    let prepared = writer.prepare_dead_replacement(actual, death)?;
                    let readback = writer.commit_dead_replacement(prepared)?;
                    if !expected.matches_state(&writer.current_source_state()?) {
                        return Err(state_error(
                            "kind5 protected postimage differs from actual owner proposal",
                        ));
                    }
                    Ok(readback)
                })
                .map_err(|_| state_error("kind5 current plan consumption failed"))??;
            if session
                .current_session_id_v2()
                .map_err(|_| state_error("kind5 post-CAS custody is stale"))?
                .as_bytes()
                != &successor.session_binding
            {
                return Err(state_error(
                    "kind5 installed successor is not current custody",
                ));
            }
            install_and_retire_kind5_runtime(runtime, &mut writer, Some(readback))
        })
        .map_err(|_| state_error("kind5 Root custody is stale"))?
        .ok_or_else(|| state_error("kind5 Root handshake is pending"))?
    }
}
