//! Authenticated controls and bounded custody renewal without Native secrets.

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

    /// Adopts Worker material with bounded per-binding authenticated renewal.
    ///
    /// Every call rechecks full current SQL pins. An independently authenticated
    /// acknowledgement may be reused for ten seconds, without extending its
    /// expiry. Cold clients always challenge Worker; operator receipts alone
    /// cannot seed this cache. This grants no execution or mutation permission.
    ///
    /// # Errors
    /// Rejects missing material, changed or unvalidated SQL pins, bad replies,
    /// expiry, or a failed exact revocation after an observed SQL race.
    pub async fn ensure_remote_binding_snapshot(
        &self,
        db: &Database,
        binding: &BindingRecord,
    ) -> Result<()> {
        let gate = self.binding_custody_cohorts.gate(binding.id)?;
        let mut custody = gate.lock().await;
        let now = aos_hub_core::clock::now_unix_secs();
        let current = self
            .current_custody_snapshot(
                db,
                binding,
                now,
                now.checked_add(3600)
                    .context("snapshot deadline overflowed")?,
            )
            .await;

        if let Some(previous) = custody.verified.as_ref() {
            let mut pinned = previous.snapshot.clone();
            pinned.issued_at = now;
            pinned.expires_at = now.saturating_add(3600);
            if !matches!(&current, Ok(snapshot) if snapshot == &pinned) {
                let revision = previous.snapshot.revision()?;
                let revoke_at = now.max(previous.snapshot.issued_at.saturating_add(1));
                custody.verified = None;
                self.revoke_binding_snapshot_locked(binding.id, &revision, revoke_at)
                    .await
                    .context("revoking changed cached custody pins")?;
                anyhow::bail!("external SQL pins changed since custody acknowledgement");
            }
            if previous.fresh(aos_hub_core::clock::now_unix_secs())
                && self.acknowledged_binding_snapshot(binding.id)? == previous.snapshot
            {
                return Ok(());
            }
        }
        // Failed refresh must never fall back to the prior acknowledgement.
        custody.verified = None;
        anyhow::ensure!(
            !custody
                .retry_after
                .is_some_and(|deadline| Instant::now() < deadline),
            "binding custody refresh is temporarily unavailable"
        );
        let mut expected = current?;
        let now = aos_hub_core::clock::now_unix_secs();
        expected.issued_at = now;
        expected.expires_at = now
            .checked_add(3600)
            .context("snapshot deadline overflowed")?;
        match self
            .refresh_custody_snapshot(db, binding, expected, now)
            .await
        {
            Ok(acknowledgement) => {
                custody.verified = Some(acknowledgement);
                custody.retry_after = None;
                Ok(())
            }
            Err(error) => {
                // Coalesce failed flights too. Queued callers refuse locally;
                // later requests may retry, without using stale custody.
                custody.retry_after = Some(Instant::now() + Duration::from_secs(1));
                Err(error)
            }
        }
    }

    async fn refresh_custody_snapshot(
        &self,
        db: &Database,
        binding: &BindingRecord,
        mut expected: StorageBindingSnapshot,
        now: i64,
    ) -> Result<super::binding_cohorts::VerifiedCustody> {
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
        let observed_at = aos_hub_core::clock::now_unix_secs();
        let verified_at = Instant::now();
        let acknowledged = verify_storage_binding_adoption_reply(
            &self.key,
            &signature,
            &body,
            &request,
            observed_at,
        )?
        .acknowledged;
        let latest = self
            .current_custody_snapshot(db, binding, acknowledged.issued_at, acknowledged.expires_at)
            .await;
        if !matches!(&latest, Ok(snapshot) if snapshot == &acknowledged) {
            self.revoke_binding_snapshot_locked(
                binding.id,
                &acknowledged.revision()?,
                aos_hub_core::clock::now_unix_secs().max(acknowledged.issued_at.saturating_add(1)),
            )
            .await
            .context("revoking binding changed during custody adoption")?;
            anyhow::bail!("external SQL pins changed during custody adoption");
        }
        // A slow SQL read cannot move the authentication window forward.
        verify_storage_binding_adoption_reply(
            &self.key,
            &signature,
            &body,
            &request,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        self.published_bindings
            .write()
            .map_err(|_| anyhow::anyhow!("published binding state poisoned"))?
            .insert(binding.id, acknowledged.clone());
        Ok(super::binding_cohorts::VerifiedCustody {
            snapshot: acknowledged,
            verified_at,
            observed_at,
        })
    }

    async fn current_custody_snapshot(
        &self,
        db: &Database,
        binding: &BindingRecord,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<StorageBindingSnapshot> {
        let current = db
            .binding(binding.id)
            .await?
            .context("external binding absent")?;
        anyhow::ensure!(
            current.stable_id == binding.stable_id
                && current.resource_version == binding.resource_version,
            "external binding changed before custody challenge"
        );
        let credentials = db.list_current_binding_credentials(binding.id).await?;
        StorageBindingSnapshot::from_binding(
            self.deployment_id.clone(),
            &current,
            &credentials,
            issued_at,
            expires_at,
        )
        .map_err(Into::into)
    }
}
