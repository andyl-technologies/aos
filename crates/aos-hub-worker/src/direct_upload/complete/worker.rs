//! Worker journals and physical guards implementing the Complete phase ports.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use worker::{Env, Request};

use super::{finish, Published, Ready, Reserved, Runtime};
use crate::direct_upload::{
    broker::{created, current, fresh_context, logical_with_context, parallelism},
    config::QualifiedConfig,
    control::LogicalReply,
    storage::{self, Operation},
    verification::{self, VerificationJob},
};

pub(super) struct WorkerRuntime<'a> {
    pub(super) request: &'a Request,
    pub(super) env: &'a Env,
    pub(super) qualified: &'a QualifiedConfig,
}

#[async_trait::async_trait(?Send)]
impl Runtime for WorkerRuntime<'_> {
    fn maximum(&self) -> usize {
        parallelism(self.qualified)
    }

    fn fresh_context(&self, original: &DirectRequestContext) -> Result<DirectRequestContext> {
        fresh_context(self.qualified, original)
    }

    async fn logical(
        &self,
        context: &DirectRequestContext,
        value: DirectUploadLogicalRequest,
    ) -> Result<LogicalReply> {
        logical_with_context(self.request, self.env, self.qualified, context, value).await
    }

    async fn prepare(
        &self,
        context: &DirectRequestContext,
        admission: DirectUploadAdmission,
        complete: DirectCompleteRequest,
    ) -> Result<Option<Ready>> {
        prepare(self.env, self.qualified, context, admission, complete).await
    }

    async fn reserve(&self, context: &DirectRequestContext, ready: Ready) -> Result<Reserved> {
        reserve(self.env, self.qualified, context, ready).await
    }

    async fn promote(&self, reserved: Reserved, permission: &LogicalReply) -> Result<Published> {
        promote(self.env, self.qualified, reserved, permission).await
    }

    async fn acknowledge(
        &self,
        item: &Published,
        committed: &LogicalReply,
        public_bytes: &[u8],
    ) -> Result<()> {
        for guard in &item.guards {
            committed
                .context
                .foreground
                .validate_at(self.qualified.latest_now()?)?;
            crate::direct_guard::acknowledge_native_commit(
                self.env,
                &item.ready.admission,
                &item.ready.complete,
                guard,
                &committed.context,
                public_bytes,
                &committed.signed.body,
                &committed.signed.signature,
            )
            .await?;
        }
        Ok(())
    }
}

async fn prepare(
    env: &Env,
    qualified: &QualifiedConfig,
    context: &DirectRequestContext,
    admission: DirectUploadAdmission,
    complete: DirectCompleteRequest,
) -> Result<Option<Ready>> {
    context.foreground.validate_at(qualified.latest_now()?)?;
    storage::call(
        env,
        &admission,
        Operation::Freeze {
            complete: complete.clone(),
        },
    )
    .await?;
    let mut verified = Vec::new();
    for placement in &admission.placements {
        if let Some(receipt) =
            verification::retained(env, &admission, &complete, placement.placement_id).await?
        {
            verified.push(receipt);
            continue;
        }

        let created = created(env, &admission, placement.placement_id).await?;
        current(qualified, context, &admission)?;
        let closed = verification::close_checked(
            env,
            &admission,
            &complete,
            placement.placement_id,
            &created,
            context.foreground.expires_at,
            || current(qualified, context, &admission),
        )
        .await?;
        let job = VerificationJob {
            version: 1,
            admission: admission.clone(),
            complete: complete.clone(),
            placement_id: placement.placement_id,
            closed,
        };
        current(qualified, context, &admission)?;
        verification::enqueue(env, &job).await?;
    }
    if verified.len() != admission.placements.len() {
        return Ok(None);
    }

    let stage = DirectVerifiedStageEvidence {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
        operation_id: complete.operation_id.clone(),
        part_count: admission.intent.part_count()?,
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        placements: verified.iter().map(|item| item.placement.clone()).collect(),
        projection: verified.first().and_then(|item| item.projection.clone()),
    };
    stage.validate_against(&admission, &context.deployment_id)?;

    let mut settled = Vec::new();
    for placement in &admission.placements {
        if let Some((evidence, guard)) = crate::direct_guard::read_publication(
            env,
            &admission,
            &complete,
            placement.placement_id,
            context,
        )
        .await?
        {
            guard.validate_placement_for(
                &admission,
                &complete,
                &evidence,
                &context.deployment_id,
            )?;
            settled.push(DirectSettledPlacement { evidence, guard });
        }
    }
    Ok(Some(Ready {
        admission,
        complete,
        stage,
        settled,
    }))
}

async fn reserve(
    env: &Env,
    qualified: &QualifiedConfig,
    context: &DirectRequestContext,
    ready: Ready,
) -> Result<Reserved> {
    let mut baselines = Vec::new();
    let mut witnesses = Vec::new();
    for placement in &ready.admission.placements {
        if ready.is_settled(placement.placement_id) {
            continue;
        }

        current(qualified, context, &ready.admission)?;
        let (baseline, witness) = crate::direct_guard::reserve_baseline(
            env,
            &ready.admission,
            &ready.complete,
            placement.placement_id,
            context,
        )
        .await?;
        baselines.push(baseline);
        witnesses.push(witness);
    }
    Ok(Reserved {
        ready,
        baselines,
        witnesses,
    })
}

async fn promote(
    env: &Env,
    qualified: &QualifiedConfig,
    reserved: Reserved,
    permission: &LogicalReply,
) -> Result<Published> {
    let Reserved {
        mut ready,
        baselines,
        witnesses,
    } = reserved;
    for ((baseline, witness), placement_id) in baselines
        .iter()
        .zip(&witnesses)
        .map(|(baseline, witness)| ((baseline, witness), baseline.binding.placement.placement_id))
    {
        let placement = storage::placement(&ready.admission, placement_id)?;
        let allowed = permission
            .reply
            .baseline_permissions
            .iter()
            .find(|value| value.binding == baseline.binding)
            .ok_or_else(|| anyhow::anyhow!("direct Native baseline permission absent"))?;
        current(qualified, &permission.context, &ready.admission)?;
        let (evidence, guard) = match placement.physical {
            DirectPhysicalContext::DeploymentR2 { .. } => {
                crate::direct_guard::promote_managed(
                    env,
                    &ready.admission,
                    &ready.complete,
                    placement_id,
                    &ready.stage,
                    baseline,
                    witness,
                    allowed,
                    &permission.context,
                    &permission.signed.body,
                    &permission.signed.signature,
                )
                .await?
            }
            DirectPhysicalContext::External { .. } => {
                crate::direct_guard::promote_external(
                    env,
                    &ready.admission,
                    &ready.complete,
                    placement_id,
                    &ready.stage,
                    baseline,
                    witness,
                    allowed,
                    &permission.context,
                    &permission.signed.body,
                    &permission.signed.signature,
                )
                .await?
            }
        };
        guard.validate_placement_for(
            &ready.admission,
            &ready.complete,
            &evidence,
            &permission.context.deployment_id,
        )?;
        ready
            .settled
            .push(DirectSettledPlacement { evidence, guard });
    }
    finish(ready, &permission.context)
}
