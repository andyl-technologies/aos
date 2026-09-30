//! Fresh controls over Worker-held credentials, without Native secret resolution.

use aos_hub_core::storage_work::binding_custody::*;

use super::*;

fn nonce() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

impl RemoteStorageWorkClient {
    /// Recovers exact historical delete material under an active frozen SQL claim.
    ///
    /// Only the separate operator process supplies a resolver. The retained
    /// generation and full claim are rechecked after the authenticated stage.
    ///
    /// # Errors
    /// Rejects changed holds or claims, mismatched material, expiry, or invalid
    /// Worker acknowledgement. It grants no provider mutation permission.
    pub async fn stage_frozen_cleanup_credential(
        &self,
        db: &Database,
        claim: &aos_hub_core::db::OciGcPlacementActionClaim,
        resolver: &dyn SecretVersionResolver,
        retention_seconds: i64,
    ) -> Result<StorageFrozenCleanupCredentialStageReply> {
        anyhow::ensure!(
            retention_seconds > 0 && retention_seconds <= MAX_CREDENTIAL_CUSTODY_SECONDS,
            "cleanup material retention must be within twenty-four hours"
        );
        let request = self.frozen_cleanup_request(db, claim).await?;
        let reference = &request.snapshot.credentials[0];
        let secret = resolver.resolve(&reference.secret_version_ref).await?;
        verify_secret_fingerprint(&secret, &reference.fingerprint)?;
        let stage = StorageFrozenCleanupCredentialStage {
            material: StorageCredentialMaterial {
                selector: StorageCredentialSelector {
                    purpose: reference.purpose.clone(),
                    generation: reference.generation,
                },
                value_base64: base64::engine::general_purpose::STANDARD
                    .encode(secret.expose_bytes()),
            },
            material_not_after: request
                .issued_at
                .checked_add(retention_seconds)
                .context("cleanup retention overflowed")?,
            request,
        };
        stage.validate(&self.deployment_id, aos_hub_core::clock::now_unix_secs())?;
        let (signature, body) = self
            .custody_exchange(
                STORAGE_FROZEN_CLEANUP_CREDENTIAL_STAGE_PATH,
                sign_storage_frozen_cleanup_credential_stage(&self.key, &stage)?,
            )
            .await?;
        let reply = verify_storage_frozen_cleanup_credential_stage_reply(
            &self.key,
            &signature,
            &body,
            &stage,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let current = db
            .active_oci_gc_placement_action_claim(
                &claim.action_id,
                &claim.claim_token,
                aos_hub_core::clock::now_unix_secs(),
            )
            .await?
            .context("cleanup claim expired during recovery")?;
        anyhow::ensure!(current == *claim, "cleanup claim changed during recovery");
        self.check_frozen_snapshot(db, &stage.request).await?;
        Ok(reply)
    }

    async fn custody_exchange(
        &self,
        path: &str,
        signed: SignedStorageCustodyControl,
    ) -> Result<(String, Vec<u8>)> {
        let endpoint = format!("{}{path}", self.executor_origin()?);
        let response = self
            .http
            .post(endpoint)
            .header("content-type", "application/json")
            .header(STORAGE_WORK_SIGNATURE_HEADER, signed.signature)
            .body(signed.body)
            .send()
            .await
            .context("sending protected credential custody challenge")?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "storage Worker rejected custody challenge with HTTP {}",
            response.status()
        );
        let signature = response
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)
            .context("custody reply signature absent")?
            .to_str()
            .context("custody reply signature malformed")?
            .to_owned();
        let body = read_bounded_response(response, MAX_BINDING_CUSTODY_BYTES).await?;
        Ok((signature, body))
    }

    /// Stages one original queued credential on Worker from an operator process.
    ///
    /// This interface resolves material only on the invoking operator machine.
    /// It produces no SQL validation, provider readiness or mutation permission.
    ///
    /// # Errors
    /// Rejects stale originals, unavailable or mismatched material, transport
    /// failure, or a changed, unauthenticated or expired acknowledgement.
    pub async fn stage_credential_custody(
        &self,
        request: StorageCredentialCustodyProbe,
        resolver: &dyn SecretVersionResolver,
        material_not_after: i64,
    ) -> Result<StorageCredentialCustodyStageReply> {
        request.validate(&self.deployment_id, aos_hub_core::clock::now_unix_secs())?;
        let reference = &request.snapshot.credentials[0];
        let secret = resolver.resolve(&reference.secret_version_ref).await?;
        verify_secret_fingerprint(&secret, &reference.fingerprint)?;
        let stage = StorageCredentialCustodyStage {
            material: StorageCredentialMaterial {
                selector: StorageCredentialSelector {
                    purpose: reference.purpose.clone(),
                    generation: reference.generation,
                },
                value_base64: base64::engine::general_purpose::STANDARD
                    .encode(secret.expose_bytes()),
            },
            request,
            material_not_after,
        };
        stage.validate(&self.deployment_id, aos_hub_core::clock::now_unix_secs())?;
        let signed = sign_storage_credential_custody_stage(&self.key, &stage)?;
        let (signature, body) = self
            .custody_exchange(STORAGE_CREDENTIAL_CUSTODY_PATH, signed)
            .await?;
        Ok(verify_storage_credential_custody_stage_reply(
            &self.key,
            &signature,
            &body,
            &stage,
            aos_hub_core::clock::now_unix_secs(),
        )?)
    }

    /// Executes the original queued probe using Worker-retained material only.
    ///
    /// # Errors
    /// Rejects unstaged or changed originals, unavailable provider evidence,
    /// mismatched authentication, or expiry during the remote exchange.
    pub async fn probe_retained_credential(
        &self,
        binding: &BindingRecord,
        credential: &BindingCredentialRevisionRecord,
        operation_id: &str,
        probe_token: &str,
    ) -> Result<StorageCredentialProbeEvidence> {
        let now = aos_hub_core::clock::now_unix_secs();
        let request = StorageCredentialCustodyProbe {
            version: 1,
            nonce: nonce(),
            issued_at: now,
            expires_at: now
                .checked_add(30)
                .context("custody probe deadline overflowed")?,
            operation_id: operation_id.into(),
            probe_token: probe_token.into(),
            head_resource_version: credential.head_resource_version,
            snapshot: StorageBindingSnapshot::for_credential_probe(
                self.deployment_id.clone(),
                binding,
                credential,
                now,
            )?,
        };
        request.validate(&self.deployment_id, now)?;
        let signed = sign_storage_credential_custody_probe(&self.key, &request)?;
        let (signature, body) = self
            .custody_exchange(STORAGE_CREDENTIAL_CUSTODY_PROBE_PATH, signed)
            .await?;
        Ok(verify_storage_credential_custody_probe_reply(
            &self.key,
            &signature,
            &body,
            &request,
            aos_hub_core::clock::now_unix_secs(),
        )?
        .evidence)
    }

    /// Adopts current Worker material under a fresh full SQL metadata challenge.
    ///
    /// This path loads no secret resolver and trusts no previous local receipt.
    /// Every invocation authenticates fresh Worker custody and rechecks SQL
    /// after the await before naming its exact acknowledged snapshot in a plan.
    ///
    /// # Errors
    /// Rejects missing material, changed or unvalidated SQL pins, bad replies,
    /// expiry, or a failed exact revocation after an observed SQL race.
    pub async fn ensure_remote_binding_snapshot(
        &self,
        db: &Database,
        binding: &BindingRecord,
    ) -> Result<()> {
        let _gate = self.binding_publication_gate.lock().await;
        let current = db
            .binding(binding.id)
            .await?
            .context("external binding absent")?;
        anyhow::ensure!(
            current.stable_id == binding.stable_id
                && current.resource_version == binding.resource_version,
            "external binding changed before custody challenge"
        );
        let now = aos_hub_core::clock::now_unix_secs();
        let credentials = db.list_current_binding_credentials(binding.id).await?;
        let mut expected = StorageBindingSnapshot::from_binding(
            self.deployment_id.clone(),
            &current,
            &credentials,
            now,
            now.checked_add(3600)
                .context("snapshot deadline overflowed")?,
        )?;
        let cached = self
            .published_bindings
            .read()
            .map_err(|_| anyhow::anyhow!("published binding state poisoned"))?
            .get(&binding.id)
            .cloned();
        if let Some(cached) = cached {
            if cached.expires_at > now.saturating_add(60)
                && cached.binding_resource_version == expected.binding_resource_version
                && cached.binding_spec_revision()? == expected.binding_spec_revision()?
                && cached.credentials == expected.credentials
            {
                expected = cached;
            }
        }
        let request = StorageBindingAdoptionRequest {
            version: 1,
            nonce: nonce(),
            issued_at: now,
            expires_at: now
                .checked_add(30)
                .context("adoption deadline overflowed")?,
            expected,
        };
        request.validate(&self.deployment_id, now)?;
        let signed = sign_storage_binding_adoption(&self.key, &request)?;
        let (signature, body) = self
            .custody_exchange(STORAGE_BINDING_ADOPTION_PATH, signed)
            .await?;
        let acknowledged = verify_storage_binding_adoption_reply(
            &self.key,
            &signature,
            &body,
            &request,
            aos_hub_core::clock::now_unix_secs(),
        )?
        .acknowledged;
        let latest = async {
            let binding = db
                .binding(binding.id)
                .await?
                .context("external binding disappeared after adoption")?;
            let credentials = db.list_current_binding_credentials(binding.id).await?;
            StorageBindingSnapshot::from_binding(
                self.deployment_id.clone(),
                &binding,
                &credentials,
                acknowledged.issued_at,
                acknowledged.expires_at,
            )
        }
        .await;
        if !matches!(&latest, Ok(snapshot) if snapshot == &acknowledged) {
            self.revoke_binding_snapshot(
                binding.id,
                &acknowledged.revision()?,
                aos_hub_core::clock::now_unix_secs().max(acknowledged.issued_at.saturating_add(1)),
            )
            .await
            .context("revoking binding changed during custody adoption")?;
            anyhow::bail!("external SQL pins changed during custody adoption");
        }
        self.published_bindings
            .write()
            .map_err(|_| anyhow::anyhow!("published binding state poisoned"))?
            .insert(binding.id, acknowledged);
        Ok(())
    }
}
