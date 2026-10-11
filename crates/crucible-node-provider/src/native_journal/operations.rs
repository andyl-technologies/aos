//! Original operation registration, native exclusivity, and retained outcomes.

use crucible_node_contract::{ContentRef, IdSet};

use crate::bodies::{BeginArguments, BeginKind, BeginRequest, OperationState, PollResult};
use crate::envelope::{MessageKind, Method, Nullable};
use crate::handshake::ResumedOperation;

use super::*;

/// Authenticates native owner coverage, binding, activation, and complete domains.
pub trait NativeScopeVerifier<C> {
    /// Resolves actual installed owner state before operation registration.
    ///
    /// # Errors
    /// Rejects stale realizations, unsupported operating modes, incomplete
    /// participant coverage, unavailable schemas, invalid causal authorization,
    /// or references not pinned by the actual native resource owner.
    fn verify_begin(
        &self,
        resources: &C,
        envelope: &Envelope,
        original: &BeginRequest,
    ) -> Result<NativeScope, ProviderError>;
}

/// Authenticates actual terminal evidence and native domain release.
pub trait NativeOutcomeVerifier<C> {
    /// Verifies original native custody and every referenced terminal receipt.
    ///
    /// # Errors
    /// Rejects foreign, unavailable, changed, or unproven native evidence.
    /// A terminal unknown error may retain `Held` domain custody; formatting a
    /// completed response cannot itself manufacture native domain release.
    fn verify_terminal(
        &self,
        resources: &C,
        original: &OperationSnapshot,
        response: &bodies::ResponseBody,
    ) -> Result<NativeDisposition, ProviderError>;
}

/// Binds one native effect attempt to its originally registered operation.
#[derive(Debug)]
pub struct NativeOperationPermit {
    identity: u64,
    operation: Id,
}

impl NativeOperationPermit {
    /// Returns the original controller-generated operation identity.
    pub fn operation_id(&self) -> &Id {
        &self.operation
    }
}

/// Distinguishes first registration from an unchanged original operation.
pub enum BeginRegistration {
    /// Reserves original custody and exclusivity before a native effect.
    New(NativeOperationPermit),
    /// Returns original retained progress without another execution permit.
    Original(Box<OperationSnapshot>),
}

impl<C: 'static> NativeJournal<C> {
    /// Reserves original operation identity and verified domain exclusivity.
    ///
    /// # Errors
    /// Rejects foreign authority/scope, changed identities or arguments, retired
    /// IDs, full ledgers, unsupported native contracts, and overlapping execution
    /// or preservation custody before issuing any native effect permit.
    pub fn register_begin(
        &mut self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        original: &BeginRequest,
        verifier: &dyn NativeScopeVerifier<C>,
    ) -> Result<BeginRegistration, ProviderError> {
        self.check_authority(authority)?;
        envelope.validate()?;
        original.validate()?;
        if envelope.method != Method::Begin || envelope.message != MessageKind::Request {
            return Err(ProviderError::Correlation(
                "native operation is not a begin request",
            ));
        }
        let RequestBody::Begin(decoded) = bodies::decode_request(Method::Begin, &envelope.body)?
        else {
            return Err(ProviderError::Frame("native begin schema mismatch"));
        };
        if &decoded != original {
            return Err(ProviderError::Conflict("original begin body changed"));
        }
        let operation = envelope
            .operation_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "begin has no operation identity",
            ))?;
        let key = request_key(envelope, RequestOrigin::Controller)?;
        let hash = envelope.request_hash(RequestOrigin::Controller)?;
        if self.custody().refused_operations.contains_key(operation) {
            return Err(ProviderError::Conflict(
                "original operation retains a not-started refusal",
            ));
        }
        if let Some(existing) = self.custody().operations.get(operation) {
            if existing.retired {
                return Err(ProviderError::Conflict("original operation retired"));
            }
            if existing.request_key != key || existing.request_hash != hash {
                return Err(ProviderError::Conflict(
                    "operation identity changed original request",
                ));
            }
            authority.ensure_live()?;
            return Ok(BeginRegistration::Original(Box::new(existing.clone())));
        }
        let live = self
            .custody()
            .operations
            .values()
            .filter(|entry| !entry.retired)
            .count();
        if live >= self.limits.operations {
            return Err(ProviderError::ResourceExhausted("native operation credit"));
        }
        let scope = verifier.verify_begin(self.resources(), envelope, original)?;
        verify_scope(envelope, original, &scope)?;
        for existing in self.custody().operations.values() {
            if !existing.domains_released
                && !existing.retired
                && conflicts(original.kind, &scope, existing)
            {
                return Err(ProviderError::Conflict(
                    "native execution or preservation domains occupied",
                ));
            }
        }
        let metadata_bytes = canonical_map(&envelope.body)?.len();
        self.preflight_metadata(envelope, metadata_bytes)?;
        authority.with_live(|| {
            let NativeRequestRegistration::New(_) =
                self.register_unfenced(envelope, RequestOrigin::Controller)?
            else {
                return Err(ProviderError::Conflict(
                    "begin request has no original native registration",
                ));
            };
            let retained_bytes = self.reserve_bytes(metadata_bytes)?;
            self.custody_mut().operations.insert(
                operation.clone(),
                OperationSnapshot {
                    operation_id: operation.clone(),
                    request_key: key,
                    request_hash: hash,
                    original: original.clone(),
                    scope,
                    state: OperationState::NotStarted,
                    cancel_requested: false,
                    domains_released: false,
                    outcome: None,
                    retired: false,
                },
            );
            self.custody_mut().retained_bytes = retained_bytes;
            Ok(BeginRegistration::New(NativeOperationPermit {
                identity: self.identity,
                operation: operation.clone(),
            }))
        })
    }

    /// Starts the sole original native effect attempt under its retained permit.
    ///
    /// The state becomes running before the callback can change resources. Any
    /// callback error retains unknown custody and domain locks; it never grants
    /// another execution attempt, even when the request connection disappears.
    ///
    /// # Errors
    /// Rejects foreign, retired, or already started operations and propagates
    /// native callback failure while preserving its complete original ledger.
    pub fn with_operation_resources<T>(
        &mut self,
        permit: &NativeOperationPermit,
        effect: impl FnOnce(&mut C) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        self.check_operation_permit(permit)?;
        let operation = self
            .custody_mut()
            .operations
            .get_mut(&permit.operation)
            .ok_or(ProviderError::Correlation("native operation disappeared"))?;
        if operation.state != OperationState::NotStarted
            || operation.outcome.is_some()
            || operation.cancel_requested
        {
            return Err(ProviderError::Conflict(
                "original native operation already attempted",
            ));
        }
        // Preserve uncertainty even if the trusted adapter unwinds after a
        // partial effect; a returned acknowledgment restores known running state.
        operation.state = OperationState::Unknown;
        let key = operation.request_key.clone();
        let reservation = self.reservation(&key)?;
        self.custody_mut().requests.mark_uncertain(&reservation)?;
        match effect(&mut self.custody_mut().resources) {
            Ok(value) => {
                self.custody_mut()
                    .operations
                    .get_mut(&permit.operation)
                    .ok_or(ProviderError::Correlation("native operation disappeared"))?
                    .state = OperationState::Running;
                Ok(value)
            }
            Err(error) => {
                self.custody_mut()
                    .operations
                    .get_mut(&permit.operation)
                    .ok_or(ProviderError::Correlation("native operation disappeared"))?
                    .state = OperationState::Unknown;
                Err(error)
            }
        }
    }

    /// Retains an original terminal begin response after native receipt verification.
    ///
    /// # Errors
    /// Rejects foreign custody, nonterminal or malformed responses, progress
    /// beyond the original grant, changed terminal material, unavailable native
    /// evidence, or exhausted retained storage. Failure retains domain locks.
    pub fn record_terminal(
        &mut self,
        permit: &NativeOperationPermit,
        outcome: &Map<String, Value>,
        verifier: &dyn NativeOutcomeVerifier<C>,
    ) -> Result<(), ProviderError> {
        self.check_operation_permit(permit)?;
        let original = self
            .custody()
            .operations
            .get(&permit.operation)
            .ok_or(ProviderError::Correlation("native operation disappeared"))?
            .clone();
        let decoded =
            bodies::decode_response(&RequestBody::Begin(original.original.clone()), outcome)?;
        if decoded.shape.is_accepted() {
            return Err(ProviderError::Conflict(
                "accepted is not a terminal operation result",
            ));
        }
        let bytes = canonical_map(outcome)?;
        if let Some(previous) = &original.outcome {
            if canonical_map(previous)? != bytes {
                return Err(ProviderError::Conflict(
                    "original terminal operation outcome changed",
                ));
            }
            return Ok(());
        }
        let retained_bytes = self.reserve_bytes(bytes.len())?;
        let disposition = verifier.verify_terminal(self.resources(), &original, &decoded)?;
        let reservation = self.reservation(&original.request_key)?;
        self.custody_mut()
            .requests
            .record_terminal(&reservation, &Value::Object(outcome.clone()))?;
        let record = self
            .custody_mut()
            .operations
            .get_mut(&permit.operation)
            .ok_or(ProviderError::Correlation("native operation disappeared"))?;
        record.state = decoded.shape.operation_state();
        record.domains_released = disposition == NativeDisposition::Released;
        record.outcome = Some(outcome.clone());
        self.custody_mut().retained_bytes = retained_bytes;
        Ok(())
    }

    /// Records a cancellation request without asserting native completion.
    ///
    /// # Errors
    /// Rejects unknown or retired operations. Existing terminal results stay
    /// unchanged and their recorded native release status remains authoritative.
    pub fn request_cancel(
        &mut self,
        operation: &Id,
    ) -> Result<bodies::CancelResult, ProviderError> {
        let record = self
            .custody_mut()
            .operations
            .get_mut(operation)
            .ok_or(ProviderError::Correlation("unknown native operation"))?;
        if record.retired {
            return Err(ProviderError::Conflict("operation retired"));
        }
        if record.outcome.is_none() {
            record.cancel_requested = true;
        }
        Ok(bodies::CancelResult {
            cancel_requested: record.cancel_requested,
            operation_state: record.state,
        })
    }

    /// Retains uncertainty after a lost native acknowledgment without retrying work.
    ///
    /// # Errors
    /// Rejects unavailable or retired operations. Existing terminal outcomes and
    /// proven native domain release are preserved unchanged.
    pub fn mark_operation_uncertain(&mut self, operation: &Id) -> Result<(), ProviderError> {
        let record = self
            .custody_mut()
            .operations
            .get_mut(operation)
            .ok_or(ProviderError::Correlation("unknown native operation"))?;
        if record.retired {
            return Err(ProviderError::Conflict("operation retired"));
        }
        if record.outcome.is_none() {
            record.state = OperationState::Unknown;
        }
        let key = record.request_key.clone();
        let reservation = self.reservation(&key)?;
        self.custody_mut().requests.mark_uncertain(&reservation)
    }

    /// Reconciles authentic completion of the original operation without a run permit.
    ///
    /// # Errors
    /// Applies the same original grant, immutable outcome, and native receipt
    /// validation as [`Self::record_terminal`]. It never starts native effects.
    pub fn reconcile_terminal(
        &mut self,
        operation: &Id,
        outcome: &Map<String, Value>,
        verifier: &dyn NativeOutcomeVerifier<C>,
    ) -> Result<(), ProviderError> {
        let permit = NativeOperationPermit {
            identity: self.identity,
            operation: operation.clone(),
        };
        self.record_terminal(&permit, outcome, verifier)
    }

    /// Authenticates later native containment while retaining the original outcome.
    ///
    /// # Errors
    /// Rejects absent terminal outcomes or native evidence that still retains
    /// unresolved domain activity. It changes no returned terminal material.
    pub fn reconcile_domain_release(
        &mut self,
        operation: &Id,
        verifier: &dyn NativeOutcomeVerifier<C>,
    ) -> Result<(), ProviderError> {
        let original = self.operation(operation)?.clone();
        let outcome = original.outcome.as_ref().ok_or(ProviderError::Conflict(
            "domain reconciliation requires original terminal outcome",
        ))?;
        let decoded =
            bodies::decode_response(&RequestBody::Begin(original.original.clone()), outcome)?;
        if verifier.verify_terminal(self.resources(), &original, &decoded)?
            != NativeDisposition::Released
        {
            return Err(ProviderError::Conflict(
                "native domains still retain unresolved custody",
            ));
        }
        self.custody_mut()
            .operations
            .get_mut(operation)
            .ok_or(ProviderError::Correlation("native operation disappeared"))?
            .domains_released = true;
        Ok(())
    }

    /// Returns retained progress and original observations after an owner cursor.
    ///
    /// # Errors
    /// Rejects unknown/retired operations, future cursors, or invalid bounds.
    pub fn poll(
        &self,
        operation: &Id,
        after: U64,
        maximum_batches: usize,
    ) -> Result<PollResult, ProviderError> {
        if let Some(refused) = self.custody().refused_operations.get(operation) {
            if after.get() != 0 {
                return Err(ProviderError::Correlation(
                    "refused operation has no observations",
                ));
            }
            return Ok(PollResult {
                operation_id: operation.clone(),
                operation_state: OperationState::NotStarted,
                outcome: Nullable(Some(refused.outcome.clone())),
                observations: Vec::new(),
                next_observation_sequence: U64::new(0),
            });
        }
        let record = self.operation(operation)?;
        let stream = OwnerStream {
            owner: record.scope.execution_owner.clone(),
            generation: record.scope.owner_generation,
        };
        let (observations, next) = self.observations_after(&stream, after, maximum_batches)?;
        let result = PollResult {
            operation_id: operation.clone(),
            operation_state: record.state,
            outcome: Nullable(record.outcome.clone()),
            observations,
            next_observation_sequence: next,
        };
        result.validate()?;
        result.validated_outcome(&record.original)?;
        Ok(result)
    }

    /// Returns exact retained states for the requested resume inventory.
    ///
    /// # Errors
    /// Rejects unsorted/duplicate, unavailable, retired, or excessive IDs.
    pub fn resumed_operations(
        &self,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        operations.validate()?;
        if operations.len() > self.limits.operations {
            return Err(ProviderError::ResourceExhausted("native resume inventory"));
        }
        operations
            .iter()
            .map(|id| {
                if let Some(refused) = self.custody().refused_operations.get(id) {
                    return Ok(ResumedOperation {
                        operation_id: id.clone(),
                        operation_state: OperationState::NotStarted,
                        outcome: Nullable(Some(refused.outcome.clone())),
                    });
                }
                let record = self.operation(id)?;
                Ok(ResumedOperation {
                    operation_id: id.clone(),
                    operation_state: record.state,
                    outcome: Nullable(record.outcome.clone()),
                })
            })
            .collect()
    }

    /// Retires an independently consumed operation while preserving its reuse tombstone.
    ///
    /// Request outcome retirement remains a separate origin-scoped transition.
    ///
    /// # Errors
    /// Rejects absent outcomes, held native domains, foreign consumption,
    /// invalid receipts, or exhausted operation tombstone storage.
    pub fn retire_operation(
        &mut self,
        operation: &Id,
        receipt: &ContentRef,
        verifier: &dyn NativeConsumptionVerifier<C>,
    ) -> Result<(), ProviderError> {
        receipt.validate()?;
        let record = self.operation(operation)?.clone();
        if record.outcome.is_none() || !record.domains_released {
            return Err(ProviderError::Conflict(
                "operation custody is not releasable",
            ));
        }
        if self
            .custody()
            .operations
            .values()
            .filter(|entry| entry.retired)
            .count()
            >= self.limits.operation_tombstones
        {
            return Err(ProviderError::ResourceExhausted(
                "native operation tombstones",
            ));
        }
        verifier.verify_operation(self.resources(), &record, receipt)?;
        let record = self
            .custody_mut()
            .operations
            .get_mut(operation)
            .ok_or(ProviderError::Correlation("native operation disappeared"))?;
        record.retired = true;
        // Payload and observation pins remain in resources until the trusted
        // consuming adapter independently discharges their complete custody.
        Ok(())
    }

    pub(super) fn operation(&self, operation: &Id) -> Result<&OperationSnapshot, ProviderError> {
        let record = self
            .custody()
            .operations
            .get(operation)
            .ok_or(ProviderError::Correlation("unknown native operation"))?;
        if record.retired {
            return Err(ProviderError::Conflict("operation retired"));
        }
        Ok(record)
    }

    pub(super) fn check_operation_permit(
        &self,
        permit: &NativeOperationPermit,
    ) -> Result<(), ProviderError> {
        if permit.identity != self.identity {
            return Err(ProviderError::Correlation(
                "foreign native operation permit",
            ));
        }
        self.operation(&permit.operation)?;
        Ok(())
    }

    pub(super) fn reservation(&self, key: &RequestKey) -> Result<Reservation, ProviderError> {
        Ok(self
            .custody()
            .reservations
            .get(key)
            .ok_or(ProviderError::Correlation(
                "native request reservation disappeared",
            ))?
            .reservation
            .clone())
    }
}

fn verify_scope(
    envelope: &Envelope,
    original: &BeginRequest,
    scope: &NativeScope,
) -> Result<(), ProviderError> {
    scope.participants.validate()?;
    scope.state_domains.validate()?;
    let preservation = matches!(
        original.kind,
        BeginKind::Capture | BeginKind::PrepareRestore
    );
    let execution_scope_matches = if preservation {
        envelope
            .execution_owner_id
            .0
            .as_ref()
            .is_none_or(|owner| owner == &scope.execution_owner)
    } else {
        envelope.execution_owner_id.0.as_ref() == Some(&scope.execution_owner)
    };
    if !execution_scope_matches
        || scope.owner_generation != original.owner_generation
        || scope.binding_hash != original.binding_hash
        || scope.participants.is_empty()
        || scope.state_domains.is_empty()
    {
        return Err(ProviderError::Correlation(
            "native scope differs from original admitted operation",
        ));
    }
    let arguments = original.decoded_arguments()?;
    let participants = match &arguments {
        BeginArguments::ExactRun(value) | BeginArguments::BoundarySettle(value) => {
            &value.participant_ids
        }
        BeginArguments::QuantumBegin(value) => &value.participant_ids,
        BeginArguments::Pause(value) => &value.participant_ids,
        BeginArguments::Capture(value) => &value.participant_ids,
        // Restore destination owner coverage is resolved from the preserved
        // manifest by the mandatory native verifier; it has no participant field.
        BeginArguments::PrepareRestore(_) => &scope.participants,
        BeginArguments::Shutdown(value) => &value.participant_ids,
    };
    if &scope.participants != participants {
        return Err(ProviderError::Correlation(
            "native operation omits or adds owner participants",
        ));
    }
    if preservation
        && (scope.capture_owner.is_none() || envelope.capture_owner_id.0 != scope.capture_owner)
    {
        return Err(ProviderError::Correlation(
            "native preservation capture owner mismatch",
        ));
    }
    Ok(())
}

fn exclusive(kind: BeginKind) -> bool {
    matches!(
        kind,
        BeginKind::ExactRun
            | BeginKind::BoundarySettle
            | BeginKind::QuantumBegin
            | BeginKind::Capture
            | BeginKind::PrepareRestore
    )
}

fn conflicts(kind: BeginKind, scope: &NativeScope, existing: &OperationSnapshot) -> bool {
    if !exclusive(kind) || !exclusive(existing.original.kind) {
        return false;
    }
    scope.execution_owner == existing.scope.execution_owner
        || (matches!(kind, BeginKind::Capture | BeginKind::PrepareRestore)
            && matches!(
                existing.original.kind,
                BeginKind::Capture | BeginKind::PrepareRestore
            )
            && scope
                .capture_owner
                .as_ref()
                .is_some_and(|owner| existing.scope.capture_owner.as_ref() == Some(owner)))
        || scope
            .state_domains
            .iter()
            .any(|domain| existing.scope.state_domains.contains(domain))
}
