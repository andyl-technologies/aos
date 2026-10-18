//! Signing helpers in the releases capability.

use super::*;

impl RpcService {
    pub(in crate::service) async fn apply_signing_key_head_mutation(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
        kind: &'static str,
        retire: bool,
    ) -> Result<pb::SigningKeyResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                kind,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, baseline, scope_key, name, mutation) = if retire {
            let (plan, input): (_, SigningKeyRetirementPlanInput) = self
                .load_control_plan(auth, &req.plan_id, kind, Some(&req.confirmation_hash))
                .await?;
            (
                plan,
                input.baseline,
                input.request.scope_key,
                input.request.name,
                None,
            )
        } else {
            let (plan, input): (_, SigningKeyMutationPlanInput) = self
                .load_control_plan(auth, &req.plan_id, kind, Some(&req.confirmation_hash))
                .await?;
            let baseline = input.baseline.ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("rotation plan omitted baseline"))
            })?;
            (
                plan,
                baseline,
                input.request.scope_key,
                input.request.name,
                Some((
                    input.request.public_key,
                    input.request.public_key_fingerprint,
                    input.request.custody,
                )),
            )
        };
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&scope_key)?;
        self.require_permission(&claims, Permission::KeysManage, &scope)
            .await?;
        let mut current = self
            .db
            .signing_key(scope.as_str(), &name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signing key"))?;
        let recovered = current.resource_version == baseline.resource_version + 1
            && if retire {
                current.state == "retired" && current.generation == baseline.generation
            } else if let Some((public_key, fingerprint, custody)) = mutation.as_ref() {
                current.state == "active"
                    && current.generation == baseline.generation + 1
                    && current.public_key == *public_key
                    && current.public_key_fingerprint == *fingerprint
                    && current.custody == *custody
            } else {
                false
            };
        if !recovered {
            if current != baseline {
                return Err(RpcError::FailedPrecondition(
                    "signing-key head changed after planning".into(),
                ));
            }
            if retire {
                self.db
                    .retire_signing_key(&baseline)
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            } else if let Some((public_key, fingerprint, custody)) = mutation {
                self.db
                    .rotate_signing_key(&baseline, &public_key, &fingerprint, &custody)
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            }
            current = self
                .db
                .signing_key(scope.as_str(), &name)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("mutated key disappeared")))?;
        }
        let response = pb::SigningKeyResponse {
            signing_key: Some(signing_key_message(current)),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
