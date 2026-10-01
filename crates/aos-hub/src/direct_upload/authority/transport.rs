//! Fresh independently authenticated protected profile and physical journal lookup.

use futures_util::StreamExt as _;

use super::*;
use aos_hub_core::storage_work::{STORAGE_CAPABILITIES_PATH, STORAGE_WORK_SIGNATURE_HEADER};

pub(super) struct VerifiedDiscovery {
    context: DirectRequestContext,
    profiles: Vec<DirectProtectedProfile>,
}

impl NativeDirectUploadAuthority {
    pub(super) async fn current_profiles(
        &self,
        context: &DirectRequestContext,
        now: i64,
    ) -> Result<Vec<DirectProtectedProfile>> {
        context.validate(&self.deployment, &self.origin, self.latest_now()?)?;
        let snapshot = self
            .discovery
            .get_or_try_init(|| async {
                let profiles = self.discover_profiles(context, now).await?;
                Ok::<_, anyhow::Error>(VerifiedDiscovery {
                    context: context.clone(),
                    profiles,
                })
            })
            .await?;
        ensure!(
            snapshot.context == *context,
            "direct discovery cannot cross invocation context"
        );
        context.validate(&self.deployment, &self.origin, self.latest_now()?)?;
        let accepted =
            self.acceptances
                .profiles(&self.deployment, &self.origin, self.latest_now()?)?;
        ensure!(
            snapshot.profiles.len() == accepted.len()
                && snapshot
                    .profiles
                    .iter()
                    .all(|profile| accepted.contains(profile)),
            "direct reviewed acceptance changed or expired during invocation"
        );
        Ok(snapshot.profiles.clone())
    }

    async fn discover_profiles(
        &self,
        context: &DirectRequestContext,
        now: i64,
    ) -> Result<Vec<DirectProtectedProfile>> {
        let accepted =
            self.acceptances
                .profiles(&self.deployment, &self.origin, self.latest_now()?)?;
        let selectors = accepted
            .iter()
            .filter_map(|item| match item {
                DirectProtectedProfile::External { profile, .. } => Some(profile.selector.clone()),
                _ => None,
            })
            .collect();
        let request = DirectStorageCapabilitiesRequest {
            version: 2,
            deployment_id: self.deployment.clone(),
            executor_public_origin: self.origin.clone(),
            request_nonce: nonce(),
            issued_at: WireInteger::new(u64::try_from(now)?),
            expires_at: context.expires_at,
            managed: accepted
                .iter()
                .any(|item| matches!(item, DirectProtectedProfile::Managed { .. })),
            external_selectors: selectors,
        };
        let signed = sign_direct_storage_capabilities_request(&self.storage_key, &request)?;
        let (signature, body) = self
            .post(
                STORAGE_CAPABILITIES_PATH,
                STORAGE_WORK_SIGNATURE_HEADER,
                signed,
                MAX_DIRECT_CAPABILITY_BYTES,
            )
            .await?;
        let reply = verify_direct_storage_capabilities_reply(
            &self.storage_key,
            &signature,
            &body,
            &request,
            self.latest_now()?,
        )?;
        let mut actual = reply
            .capabilities
            .external_profiles
            .into_iter()
            .map(|profile| DirectProtectedProfile::External {
                profile: profile.profile,
                runtime_qualification: profile.runtime_qualification,
            })
            .collect::<Vec<_>>();
        if let (Some(profile), Some(policy), Some(runtime)) = (
            reply.capabilities.profile,
            reply.capabilities.private_stage_policy,
            reply.capabilities.runtime_qualification,
        ) {
            actual.push(DirectProtectedProfile::managed(profile, policy, runtime)?);
        }
        ensure!(
            actual.len() == accepted.len() && actual.iter().all(|item| accepted.contains(item)),
            "direct actual protected profiles differ from independently reviewed acceptance"
        );
        Ok(actual)
    }

    pub(super) async fn lookup_stage(
        &self,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectVerifiedStageEvidence,
        now: i64,
    ) -> Result<()> {
        self.lookup_authority(
            context,
            DirectAuthorityLookupOperation::Stage {
                admission: record.admission.clone(),
                complete: record
                    .complete_intent
                    .clone()
                    .context("direct Complete original absent")?,
                evidence: evidence.clone(),
            },
            now,
        )
        .await
    }

    pub(super) async fn lookup_baseline(
        &self,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectDestinationBaselineEvidence,
        witness: &DirectDestinationBaselineWitness,
        now: i64,
    ) -> Result<()> {
        self.lookup_authority(
            context,
            DirectAuthorityLookupOperation::Baseline {
                admission: record.admission.clone(),
                complete: record
                    .complete_intent
                    .clone()
                    .context("direct Complete original absent")?,
                evidence: evidence.clone(),
                witness: witness.clone(),
            },
            now,
        )
        .await
    }

    pub(super) async fn lookup_authority(
        &self,
        context: &DirectRequestContext,
        operation: DirectAuthorityLookupOperation,
        now: i64,
    ) -> Result<()> {
        let request = DirectAuthorityLookup {
            deployment_id: self.deployment.clone(),
            request_nonce: nonce(),
            issued_at: WireInteger::new(u64::try_from(now)?),
            expires_at: context.expires_at,
            operation,
        };
        let signed = sign_direct_authority_lookup(&self.guard_key, &request)?;
        let (signature, body) = self
            .post(
                DIRECT_AUTHORITY_LOOKUP_PATH,
                DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER,
                signed,
                MAX_DIRECT_CONTROL_BYTES,
            )
            .await?;
        verify_direct_authority_lookup_reply(
            &self.guard_key,
            &signature,
            &body,
            &request,
            self.latest_now()?,
        )?;
        Ok(())
    }

    pub(super) async fn lookup_final(
        &self,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        expected: &DirectFinalGuardRecord,
        now: i64,
    ) -> Result<()> {
        let request = DirectFinalGuardLookup {
            admission: record.admission.clone(),
            complete: record
                .complete_intent
                .clone()
                .context("direct Complete original absent")?,
            expected: expected.clone(),
            request_nonce: nonce(),
            issued_at: WireInteger::new(u64::try_from(now)?),
            expires_at: context.expires_at,
        };
        let signed = sign_direct_final_guard_lookup(&self.guard_key, &request)?;
        let (signature, body) = self
            .post(
                DIRECT_FINAL_GUARD_PATH,
                DIRECT_FINAL_GUARD_SIGNATURE_HEADER,
                signed,
                MAX_DIRECT_CONTROL_BYTES,
            )
            .await?;
        verify_direct_final_guard_reply(
            &self.guard_key,
            &signature,
            &body,
            &request,
            self.latest_now()?,
        )?;
        Ok(())
    }

    async fn post(
        &self,
        path: &str,
        header: &str,
        signed: SignedDirectControl,
        maximum_bytes: usize,
    ) -> Result<(String, Vec<u8>)> {
        let _permit = self.lookup_slots.acquire().await?;
        let response = self
            .http
            .post(format!("{}{}", self.origin, path))
            .header(header, signed.signature)
            .body(signed.body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("independent direct authority unavailable"))?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "independent direct authority refused lookup"
        );
        let signature = response
            .headers()
            .get(header)
            .context("direct authority reply signature absent")?
            .to_str()?
            .to_owned();
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| anyhow::anyhow!("direct authority reply unreadable"))?;
            ensure!(
                body.len().saturating_add(chunk.len()) <= maximum_bytes,
                "direct authority reply exceeds bound"
            );
            body.extend_from_slice(&chunk);
        }
        Ok((signature, body))
    }
}

fn nonce() -> String {
    use rand::RngCore as _;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
