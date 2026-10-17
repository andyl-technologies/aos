//! Trusted reconciliation of original request outcomes without replacement effects.

use super::*;

/// Verifies an original response against actual retained native acknowledgment.
///
/// A verifier belongs to installed adapter code and binds authenticated transport
/// evidence to retained resources. Portable response fields alone cannot satisfy
/// this interface or mint another effect permit.
pub trait NativeRequestOutcomeVerifier<C: 'static> {
    /// Verifies complete original request material and genuine native completion.
    ///
    /// # Errors
    /// Rejects missing native evidence, foreign original scope, or an outcome
    /// that cannot be proved from the actual surviving resources.
    fn verify_request_outcome(
        &self,
        resources: &C,
        original: &Envelope,
        response: &bodies::ResponseBody,
    ) -> Result<(), ProviderError>;
}

impl<C: 'static> NativeJournal<C> {
    /// Retains a proved not-started refusal before any resource callback begins.
    ///
    /// A refused begin reserves its original operation commitment but supplies no
    /// execution/capture scope or effect permit. Identical retries retain this
    /// refusal; changed material or replacement requests cannot reuse the ID.
    ///
    /// # Errors
    /// Rejects foreign or started permits, non-refusal or uncertain responses,
    /// operation collisions, full refusal tombstone storage, and changed outcomes.
    pub fn record_request_refusal(
        &mut self,
        permit: &NativeRequestPermit,
        outcome: &Map<String, Value>,
    ) -> Result<(), ProviderError> {
        self.check_request_permit(permit)?;
        let record =
            self.custody()
                .reservations
                .get(&permit.key)
                .ok_or(ProviderError::Correlation(
                    "original refusal reservation missing",
                ))?;
        if record.started {
            return Err(ProviderError::Conflict(
                "started effects cannot claim not-started refusal",
            ));
        }
        let request = bodies::decode_request(record.original.method, &record.original.body)?;
        let response = bodies::decode_response(&request, outcome)?;
        if !matches!(
            response.shape,
            bodies::ResponseShape::Error {
                operation_state: bodies::OperationState::NotStarted,
                error: bodies::ErrorRecord {
                    effect: bodies::EffectCertainty::NotStarted,
                    ..
                },
                ..
            }
        ) {
            return Err(ProviderError::Conflict(
                "refusal must prove not-started effects",
            ));
        }
        let reservation = record.reservation.clone();
        let refused = if matches!(request, RequestBody::Begin(_)) {
            let operation =
                record
                    .original
                    .operation_id
                    .0
                    .clone()
                    .ok_or(ProviderError::Correlation(
                        "refused begin operation missing",
                    ))?;
            let hash = record.original.request_hash(RequestOrigin::Controller)?;
            if self
                .custody()
                .operations
                .get(&operation)
                .is_some_and(|original| original.request_key == permit.key)
            {
                return Err(ProviderError::Conflict(
                    "accepted operation requires original native outcome verifier",
                ));
            }
            let occupied_by_other = self.custody().operations.contains_key(&operation)
                || self
                    .custody()
                    .refused_operations
                    .get(&operation)
                    .is_some_and(|original| original.request_key != permit.key);
            if occupied_by_other {
                None
            } else {
                if self
                    .custody()
                    .refused_operations
                    .get(&operation)
                    .is_some_and(|original| {
                        original.request_key != permit.key
                            || original.request_hash != hash
                            || &original.outcome != outcome
                    })
                {
                    return Err(ProviderError::Conflict(
                        "refused operation changed original commitment",
                    ));
                }
                if !self.custody().refused_operations.contains_key(&operation)
                    && self.custody().refused_operations.len() >= self.limits.operation_tombstones
                {
                    return Err(ProviderError::ResourceExhausted(
                        "refused operation tombstones",
                    ));
                }
                Some(RefusedOperation {
                    node_id: record.original.node_id.0.clone(),
                    execution_owner_id: record.original.execution_owner_id.0.clone(),
                    capture_owner_id: record.original.capture_owner_id.0.clone(),
                    operation_id: operation,
                    request_key: permit.key.clone(),
                    request_hash: hash,
                    outcome: outcome.clone(),
                })
            }
        } else {
            None
        };
        let retained_bytes = if let Some(refused) = &refused {
            if self
                .custody()
                .refused_operations
                .contains_key(&refused.operation_id)
            {
                self.custody().retained_bytes
            } else {
                let scope_bytes = [
                    &refused.node_id,
                    &refused.execution_owner_id,
                    &refused.capture_owner_id,
                ]
                .into_iter()
                .flatten()
                .map(|id| id.as_str().len())
                .sum::<usize>();
                self.reserve_bytes(
                    canonical_map(outcome)?
                        .len()
                        .checked_add(scope_bytes)
                        .ok_or(ProviderError::ResourceExhausted("refused scope bytes"))?,
                )?
            }
        } else {
            self.custody().retained_bytes
        };
        self.custody_mut()
            .requests
            .record_terminal(&reservation, &Value::Object(outcome.clone()))?;
        if let Some(refused) = refused {
            self.custody_mut().retained_bytes = retained_bytes;
            self.custody_mut()
                .refused_operations
                .insert(refused.operation_id.clone(), refused);
        }
        Ok(())
    }

    /// Reconciles a retained original response without permitting another effect.
    ///
    /// This path completes an original uncertain request after its authenticated
    /// acknowledgment is recovered. It never returns resource access or resets
    /// the request, operation, or stream identity.
    ///
    /// # Errors
    /// Rejects revoked authority, absent or changed original requests, begin
    /// operations, nonterminal bodies, unsupported native proof, or changed
    /// retained outcomes and exhausted outcome storage.
    pub fn reconcile_request_terminal(
        &mut self,
        authority: &ConnectionAuthority,
        original: &Envelope,
        origin: RequestOrigin,
        outcome: &Map<String, Value>,
        verifier: &dyn NativeRequestOutcomeVerifier<C>,
    ) -> Result<(), ProviderError> {
        self.check_authority(authority)?;
        authority.with_live(|| {
            let key = request_key(original, origin)?;
            let record =
                self.custody()
                    .reservations
                    .get(&key)
                    .ok_or(ProviderError::Correlation(
                        "original request custody unavailable",
                    ))?;
            if record.original.request_hash(origin)? != original.request_hash(origin)? {
                return Err(ProviderError::Conflict(
                    "reconciliation changed original request",
                ));
            }
            let request = bodies::decode_request(record.original.method, &record.original.body)?;
            if matches!(request, RequestBody::Begin(_)) {
                return Err(ProviderError::Conflict(
                    "begin reconciliation requires original operation verifier",
                ));
            }
            let response = bodies::decode_response(&request, outcome)?;
            if response.shape.is_accepted() {
                return Err(ProviderError::Conflict(
                    "reconciliation requires terminal outcome",
                ));
            }
            verifier.verify_request_outcome(
                &self.custody().resources,
                &record.original,
                &response,
            )?;
            let reservation = record.reservation.clone();
            self.custody_mut()
                .requests
                .record_terminal(&reservation, &Value::Object(outcome.clone()))
        })
    }
}
