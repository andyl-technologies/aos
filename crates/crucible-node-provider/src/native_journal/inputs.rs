//! Immutable input batches and native payload custody across uncertain retries.

use crucible_node_contract::InputBatch;

use crate::bodies::{InputRequest, InputResult, OperationState};
use crate::envelope::{MessageKind, Method};

use super::*;

/// Verifies and accepts input using installed native owner and content custody.
pub trait NativeInputVerifier<C> {
    /// Verifies scope, epoch, admissible input phase, and every pinned payload.
    ///
    /// # Errors
    /// Refuses unsupported input timing, stale owner bindings, unavailable
    /// payloads, invalid schema/provenance, or incomplete native input custody.
    fn verify_input(
        &self,
        resources: &C,
        envelope: &Envelope,
        original: &InputRequest,
        batch: &InputBatch,
    ) -> Result<(), ProviderError>;

    /// Transfers accepted input and complete content pins into native resources.
    ///
    /// This callback must only establish input custody; it cannot execute guest
    /// work. A failure is uncertain and must preserve any partially acquired
    /// native custody inside `resources` for reconciliation, never reacceptance.
    ///
    /// # Errors
    /// Reports failed or unresolved native input custody without implying rollback.
    fn accept_input(
        &self,
        resources: &mut C,
        batch: &InputBatch,
    ) -> Result<InputResult, ProviderError>;
}

/// Recovers actual original input custody without repeating native acceptance.
pub trait NativeInputReconciler<C> {
    /// Reads the surviving native owner's original accepted batch and receipt.
    ///
    /// Implementations must not rerun acceptance or manufacture another batch.
    ///
    /// # Errors
    /// Refuses uncertain, absent, changed, or unavailable original input custody.
    fn recover_input(
        &self,
        resources: &C,
        original: &InputSnapshot,
    ) -> Result<InputResult, ProviderError>;
}

/// Distinguishes first native input acceptance from original retained custody.
pub enum InputAcceptance {
    /// Returns the first authenticated accepted-input receipt.
    Accepted(InputResult),
    /// Returns original accepted or uncertain custody without rerunning acceptance.
    Original(Box<InputSnapshot>),
}

impl<C: 'static> NativeJournal<C> {
    /// Preserves and accepts a complete original ordered input batch exactly once.
    ///
    /// A stream starts at batch sequence one. Native verification binds the first
    /// epoch; later requests cannot change it or reset the sequence on reconnect.
    /// Full batch material is reserved before the native acceptance callback.
    ///
    /// # Errors
    /// Rejects foreign authority, changed batch/request identities, sequence gaps,
    /// epoch changes, repeated producer sequences, missing content custody, full
    /// ledgers, or an uncertain prior acceptance. Native failure remains retained.
    pub fn accept_input(
        &mut self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        original: &InputRequest,
        verifier: &dyn NativeInputVerifier<C>,
    ) -> Result<InputAcceptance, ProviderError> {
        self.check_authority(authority)?;
        envelope.validate()?;
        original.validate()?;
        if envelope.method != Method::Input || envelope.message != MessageKind::Request {
            return Err(ProviderError::Correlation(
                "native input is not an input request",
            ));
        }
        let RequestBody::Input(decoded) = bodies::decode_request(Method::Input, &envelope.body)?
        else {
            return Err(ProviderError::Frame("native input schema mismatch"));
        };
        if &decoded != original {
            return Err(ProviderError::Conflict("native input body changed"));
        }
        let owner = envelope
            .execution_owner_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("input has no execution owner"))?;
        let batch = original.verified_batch(owner)?;
        let stream = OwnerStream {
            owner: owner.clone(),
            generation: original.owner_generation,
        };
        let input_key = (stream.clone(), batch.batch_id.clone());
        let key = request_key(envelope, RequestOrigin::Controller)?;
        let request_hash = envelope.request_hash(RequestOrigin::Controller)?;
        if let Some(existing) = self.custody().inputs.get(&input_key) {
            if existing.batch_hash != original.batch_hash
                || existing.request_key != key
                || existing.request_hash != request_hash
            {
                return Err(ProviderError::Conflict(
                    "original input custody changed material",
                ));
            }
            return Ok(InputAcceptance::Original(Box::new(existing.clone())));
        }
        if self.custody().inputs.len() >= self.limits.input_batches {
            return Err(ProviderError::ResourceExhausted(
                "native input batch credit",
            ));
        }
        let next = if let Some(existing) = self.custody().input_streams.get(&stream) {
            if existing.epoch != batch.input_epoch {
                return Err(ProviderError::Conflict("native input epoch cannot reset"));
            }
            existing.next_sequence
        } else {
            U64::new(1)
        };
        if batch.batch_sequence != next {
            return Err(ProviderError::Conflict(
                "native input batch sequence is not contiguous",
            ));
        }
        let successor = next.checked_add(U64::new(1))?;
        for retained in self
            .custody()
            .inputs
            .values()
            .filter(|entry| entry.stream == stream)
        {
            if retained.state != OperationState::Completed {
                return Err(ProviderError::Conflict(
                    "previous native input custody is unresolved",
                ));
            }
            if retained.batch.events.iter().any(|old| {
                batch.events.iter().any(|new| {
                    old.source.node_id == new.source.node_id
                        && old.source_sequence == new.source_sequence
                })
            }) {
                return Err(ProviderError::Conflict(
                    "producer sequence repeats across input batches",
                ));
            }
        }
        verifier.verify_input(self.resources(), envelope, original, &batch)?;
        let metadata_bytes = canonical_map(&envelope.body)?.len();
        self.preflight_metadata(envelope, metadata_bytes)?;
        let request_permit = authority.with_live(|| {
            let NativeRequestRegistration::New(permit) =
                self.register_unfenced(envelope, RequestOrigin::Controller)?
            else {
                return Err(ProviderError::Conflict(
                    "input request has no original native registration",
                ));
            };
            let retained_bytes = self.reserve_bytes(metadata_bytes)?;
            self.custody_mut().inputs.insert(
                input_key.clone(),
                InputSnapshot {
                    stream: stream.clone(),
                    batch: batch.clone(),
                    batch_hash: original.batch_hash.clone(),
                    request_key: key,
                    request_hash,
                    state: OperationState::Unknown,
                    result: None,
                },
            );
            self.custody_mut().retained_bytes = retained_bytes;
            Ok(permit)
        })?;
        let result = self.with_request_resources(&request_permit, |resources| {
            verifier.accept_input(resources, &batch)
        })?;
        result.validate()?;
        if result.input_watermark != batch.batch_sequence {
            return Err(ProviderError::Correlation(
                "native input receipt changed contiguous watermark",
            ));
        }
        let response = serde_json::json!({"status":"completed","operation_state":"completed","result":result,"extensions":{}});
        let response = response
            .as_object()
            .ok_or(ProviderError::Frame("input outcome must be an object"))?;
        self.record_request_terminal(&request_permit, response)?;
        let snapshot =
            self.custody_mut()
                .inputs
                .get_mut(&input_key)
                .ok_or(ProviderError::Correlation(
                    "native input custody disappeared",
                ))?;
        snapshot.state = OperationState::Completed;
        snapshot.result = Some(result.clone());
        self.custody_mut().input_streams.insert(
            stream,
            InputCursor {
                epoch: batch.input_epoch,
                next_sequence: successor,
            },
        );
        Ok(InputAcceptance::Accepted(result))
    }

    /// Returns an immutable retained input batch beneath its original owner scope.
    pub fn input(&self, stream: &OwnerStream, batch: &Id) -> Option<&InputSnapshot> {
        self.custody().inputs.get(&(stream.clone(), batch.clone()))
    }

    /// Reconciles a lost original input acknowledgment without reaccepting input.
    ///
    /// # Errors
    /// Rejects unknown or changed native custody, malformed receipts, wrong
    /// watermarks, and exhausted outcome storage. The original snapshot remains
    /// uncertain until every validation and retained terminal write succeeds.
    pub fn reconcile_input(
        &mut self,
        stream: &OwnerStream,
        batch: &Id,
        verifier: &dyn NativeInputReconciler<C>,
    ) -> Result<InputResult, ProviderError> {
        let key = (stream.clone(), batch.clone());
        let original = self
            .custody()
            .inputs
            .get(&key)
            .ok_or(ProviderError::Correlation("unknown native input batch"))?
            .clone();
        if let Some(result) = original.result {
            return Ok(result);
        }
        let result = verifier.recover_input(self.resources(), &original)?;
        result.validate()?;
        if result.input_watermark != original.batch.batch_sequence {
            return Err(ProviderError::Correlation(
                "recovered input changed original watermark",
            ));
        }
        let successor = original.batch.batch_sequence.checked_add(U64::new(1))?;
        let request = self
            .custody()
            .reservations
            .get(&original.request_key)
            .ok_or(ProviderError::Correlation(
                "original input request disappeared",
            ))?;
        let decoded = bodies::decode_request(request.original.method, &request.original.body)?;
        let response = serde_json::json!({"status":"completed","operation_state":"completed","result":result,"extensions":{}});
        let response = response
            .as_object()
            .ok_or(ProviderError::Frame("input outcome must be an object"))?;
        bodies::decode_response(&decoded, response)?;
        let reservation = request.reservation.clone();
        self.custody_mut()
            .requests
            .record_terminal(&reservation, &Value::Object(response.clone()))?;
        let record = self
            .custody_mut()
            .inputs
            .get_mut(&key)
            .ok_or(ProviderError::Correlation(
                "original input custody disappeared",
            ))?;
        record.result = Some(result.clone());
        record.state = OperationState::Completed;
        self.custody_mut().input_streams.insert(
            stream.clone(),
            InputCursor {
                epoch: original.batch.input_epoch,
                next_sequence: successor,
            },
        );
        Ok(result)
    }
}
