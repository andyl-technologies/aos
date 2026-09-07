//! Bounded durable publisher execution and challenge registration audit.
//!
//! Namespace 9 contains immutable execution facts and exact challenge requests.
//! These records never reconstruct live sessions, consume challenges, reserve
//! capacity for publication, or grant signing/completion authority. All challenge
//! keys remain retained, including expired ones: finite lifetime quotas prevent
//! replay through deletion and slot reuse. Future admission must consume a
//! challenge atomically with its decision and reservation in the sole journal.
//!
//! This facade assumes exclusive trusted ownership of the namespace. Canonical
//! replay detects malformed state, not validly encoded malicious rewrites by
//! another privileged journal writer or rollback of the whole protected store.

use std::collections::BTreeMap;

use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::{PublisherChallengeV1, PublisherInstanceId};

mod model;
mod record;
pub use model::{
    PublisherChallengeDraftV1, PublisherChallengeRegistrationV1, PublisherExecutionDraftV1,
    PublisherExecutionRegistrationV1,
};

const EXECUTION_PREFIX: &[u8] = b"execution/";
const CHALLENGE_PREFIX: &[u8] = b"challenge/";
const HARD_RECORD_BYTES: usize = 65_536;

/// Bounds retained audit state, including every expired challenge key.
#[derive(Clone, Copy, Debug)]
pub struct PublisherIngressLimits {
    maximum_executions: usize,
    maximum_challenges: usize,
    maximum_challenges_per_execution: usize,
    maximum_record_bytes: usize,
    maximum_materialized_bytes: usize,
}

impl PublisherIngressLimits {
    /// Constructs bounded replay and lifetime-registration limits.
    ///
    /// # Errors
    /// Rejects zero limits or hard ceilings above 65536 executions/challenges,
    /// 4096 challenges per execution, 64 KiB per record, or 256 MiB total.
    pub fn new(
        maximum_executions: usize,
        maximum_challenges: usize,
        maximum_challenges_per_execution: usize,
        maximum_record_bytes: usize,
        maximum_materialized_bytes: usize,
    ) -> Result<Self, PublisherIngressError> {
        if maximum_executions == 0
            || maximum_executions > 65_536
            || maximum_challenges == 0
            || maximum_challenges > 65_536
            || maximum_challenges_per_execution == 0
            || maximum_challenges_per_execution > 4096
            || maximum_record_bytes == 0
            || maximum_record_bytes > HARD_RECORD_BYTES
            || maximum_materialized_bytes == 0
            || maximum_materialized_bytes > 256 * 1024 * 1024
        {
            return Err(PublisherIngressError::InvalidLimits);
        }
        Ok(Self {
            maximum_executions,
            maximum_challenges,
            maximum_challenges_per_execution,
            maximum_record_bytes,
            maximum_materialized_bytes,
        })
    }
}

impl Default for PublisherIngressLimits {
    fn default() -> Self {
        Self {
            maximum_executions: 1024,
            maximum_challenges: 16_384,
            maximum_challenges_per_execution: 1024,
            maximum_record_bytes: HARD_RECORD_BYTES,
            maximum_materialized_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Reports durable audit validation and registration failures.
#[derive(Debug, thiserror::Error)]
pub enum PublisherIngressError {
    /// A configured bound is zero or exceeds the hard profile.
    #[error("invalid publisher ingress limits")]
    InvalidLimits,
    /// Facts contain a sentinel or invalid time/process/domain profile.
    #[error("invalid publisher ingress facts")]
    InvalidFacts,
    /// A key, version, canonical record or request encoding is malformed.
    #[error("malformed publisher ingress record")]
    MalformedRecord,
    /// A challenge disagrees with its immutable registered execution.
    #[error("publisher challenge execution binding mismatch")]
    ExecutionMismatch,
    /// No execution was registered for this instance.
    #[error("publisher execution is not registered")]
    UnknownExecution,
    /// An immutable key was already used for different facts.
    #[error("publisher ingress identity already has different facts")]
    IdentityConflict,
    /// A finite lifetime or serialization budget is exhausted.
    #[error("publisher ingress limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Protected storage failed or became poisoned.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Distinguishes a durable insertion from exact immutable audit replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublisherIngressWriteOutcome {
    /// New facts were durably installed.
    Inserted,
    /// Exact facts were already retained; this does not recreate a live session.
    AlreadyPresent,
}

/// Exclusively borrows the sole journal writer for validated ingress audit state.
pub struct PublisherIngressStore<'a> {
    journal: &'a mut Journal,
    limits: PublisherIngressLimits,
    executions: usize,
    challenges: usize,
    bytes: usize,
    per_execution: BTreeMap<[u8; 16], usize>,
}

impl<'a> PublisherIngressStore<'a> {
    /// Replays every retained record and validates all execution cross-links.
    ///
    /// # Errors
    /// Rejects unprotected/poisoned storage, malformed records, orphan challenges,
    /// mismatched scopes or exhausted count/byte bounds before allowing reads.
    pub fn load(
        journal: &'a mut Journal,
        limits: PublisherIngressLimits,
    ) -> Result<Self, PublisherIngressError> {
        journal.ensure_protected_authority()?;
        let mut executions = 0usize;
        let mut challenges = 0usize;
        let mut bytes = 0usize;
        let mut per_execution = BTreeMap::new();
        // Bound the entire namespace before allocating decoded records.
        for (key, value) in journal.records(RecordNamespace::PublisherIngress) {
            if value.len() > limits.maximum_record_bytes {
                return Err(PublisherIngressError::LimitExceeded("record bytes"));
            }
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(PublisherIngressError::LimitExceeded("materialized bytes"))?;
            if bytes > limits.maximum_materialized_bytes {
                return Err(PublisherIngressError::LimitExceeded("materialized bytes"));
            }
            match record::parse_key(key)? {
                record::Key::Execution(_) => {
                    executions += 1;
                    if executions > limits.maximum_executions {
                        return Err(PublisherIngressError::LimitExceeded("executions"));
                    }
                }
                record::Key::Challenge(instance, _) => {
                    challenges += 1;
                    if challenges > limits.maximum_challenges {
                        return Err(PublisherIngressError::LimitExceeded("challenges"));
                    }
                    if !per_execution.contains_key(&instance)
                        && per_execution.len() >= limits.maximum_executions
                    {
                        return Err(PublisherIngressError::LimitExceeded(
                            "challenge execution count",
                        ));
                    }
                    let count = per_execution.entry(instance).or_insert(0usize);
                    *count += 1;
                    if *count > limits.maximum_challenges_per_execution {
                        return Err(PublisherIngressError::LimitExceeded(
                            "per-execution challenges",
                        ));
                    }
                }
            }
        }
        let store = Self {
            journal,
            limits,
            executions,
            challenges,
            bytes,
            per_execution,
        };
        for (key, value) in store.journal.records(RecordNamespace::PublisherIngress) {
            match record::parse_key(key)? {
                record::Key::Execution(instance) => {
                    let decoded = record::decode_execution(value, limits.maximum_record_bytes)?;
                    if decoded.fields().instance.as_bytes() != &instance {
                        return Err(PublisherIngressError::MalformedRecord);
                    }
                }
                record::Key::Challenge(instance, challenge) => {
                    let decoded = record::decode_challenge(value, limits.maximum_record_bytes)?;
                    validate_challenge_key(&decoded, instance, challenge)?;
                    decoded.validate_execution(
                        &store
                            .execution(PublisherInstanceId::from_bytes(instance))?
                            .ok_or(PublisherIngressError::UnknownExecution)?,
                    )?;
                }
            }
        }
        Ok(store)
    }

    /// Reads immutable execution audit facts, never a live publisher identity.
    ///
    /// # Errors
    /// Rejects unhealthy storage, sentinel keys, or malformed retained facts.
    pub fn execution(
        &self,
        instance: PublisherInstanceId,
    ) -> Result<Option<PublisherExecutionRegistrationV1>, PublisherIngressError> {
        self.journal.ensure_protected_authority()?;
        let key = record::execution_key(instance)?;
        self.journal
            .get(RecordNamespace::PublisherIngress, &key)
            .map(|bytes| {
                let value = record::decode_execution(bytes, self.limits.maximum_record_bytes)?;
                if value.fields().instance != instance {
                    return Err(PublisherIngressError::MalformedRecord);
                }
                Ok(value)
            })
            .transpose()
    }

    /// Reads an immutable registered request, including expired registrations.
    ///
    /// # Errors
    /// Rejects unhealthy storage, malformed records or missing execution links.
    pub fn challenge(
        &self,
        instance: PublisherInstanceId,
        challenge: PublisherChallengeV1,
    ) -> Result<Option<PublisherChallengeRegistrationV1>, PublisherIngressError> {
        self.journal.ensure_protected_authority()?;
        let key = record::challenge_key(instance, challenge)?;
        self.journal
            .get(RecordNamespace::PublisherIngress, &key)
            .map(|bytes| {
                let value = record::decode_challenge(bytes, self.limits.maximum_record_bytes)?;
                validate_challenge_key(&value, *instance.as_bytes(), *challenge.as_bytes())?;
                value.validate_execution(
                    &self
                        .execution(instance)?
                        .ok_or(PublisherIngressError::UnknownExecution)?,
                )?;
                Ok(value)
            })
            .transpose()
    }

    pub(crate) fn install_execution(
        &mut self,
        transaction_id: [u8; 16],
        registration: PublisherExecutionRegistrationV1,
    ) -> Result<PublisherIngressWriteOutcome, PublisherIngressError> {
        self.journal.ensure_protected_authority()?;
        let key = record::execution_key(registration.fields().instance)?;
        let value = record::encode_execution(&registration, self.limits.maximum_record_bytes)?;
        if self
            .journal
            .get(RecordNamespace::PublisherIngress, &key)
            .is_some()
        {
            return Err(PublisherIngressError::IdentityConflict);
        }
        if self.executions >= self.limits.maximum_executions {
            return Err(PublisherIngressError::LimitExceeded("executions"));
        }
        self.commit(transaction_id, key, value)?;
        self.executions += 1;
        Ok(PublisherIngressWriteOutcome::Inserted)
    }

    pub(crate) fn register_challenge(
        &mut self,
        transaction_id: [u8; 16],
        registration: PublisherChallengeRegistrationV1,
    ) -> Result<PublisherIngressWriteOutcome, PublisherIngressError> {
        self.journal.ensure_protected_authority()?;
        let request = &registration.fields().request;
        let instance = request.plan().fields().target.instance;
        registration.validate_execution(
            &self
                .execution(instance)?
                .ok_or(PublisherIngressError::UnknownExecution)?,
        )?;
        let key = record::challenge_key(instance, request.challenge())?;
        let value = record::encode_challenge(&registration, self.limits.maximum_record_bytes)?;
        if let Some(outcome) = self.existing(&key, &value)? {
            return Ok(outcome);
        }
        if self.challenges >= self.limits.maximum_challenges {
            return Err(PublisherIngressError::LimitExceeded("challenges"));
        }
        let count = self
            .per_execution
            .get(instance.as_bytes())
            .copied()
            .unwrap_or(0);
        if count >= self.limits.maximum_challenges_per_execution {
            return Err(PublisherIngressError::LimitExceeded(
                "per-execution challenges",
            ));
        }
        // Reserve the small counter entry before durability; failure cannot
        // expose an uncounted successful registration through this facade.
        self.per_execution
            .entry(*instance.as_bytes())
            .or_insert(count);
        self.commit(transaction_id, key, value)?;
        self.challenges += 1;
        self.per_execution.insert(*instance.as_bytes(), count + 1);
        Ok(PublisherIngressWriteOutcome::Inserted)
    }

    fn existing(
        &self,
        key: &[u8],
        value: &[u8],
    ) -> Result<Option<PublisherIngressWriteOutcome>, PublisherIngressError> {
        self.journal.ensure_protected_authority()?;
        match self.journal.get(RecordNamespace::PublisherIngress, key) {
            None => Ok(None),
            Some(existing) if existing == value => {
                Ok(Some(PublisherIngressWriteOutcome::AlreadyPresent))
            }
            Some(_) => Err(PublisherIngressError::IdentityConflict),
        }
    }

    fn commit(
        &mut self,
        id: [u8; 16],
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), PublisherIngressError> {
        let bytes = self
            .bytes
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(PublisherIngressError::LimitExceeded("materialized bytes"))?;
        if bytes > self.limits.maximum_materialized_bytes {
            return Err(PublisherIngressError::LimitExceeded("materialized bytes"));
        }
        self.journal.commit(&JournalTransaction::new(
            id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherIngress,
                key,
                value,
            )],
        )?)?;
        self.bytes = bytes;
        Ok(())
    }
}

fn validate_challenge_key(
    value: &PublisherChallengeRegistrationV1,
    instance: [u8; 16],
    challenge: [u8; 32],
) -> Result<(), PublisherIngressError> {
    let request = &value.fields().request;
    if request.plan().fields().target.instance.as_bytes() != &instance
        || request.challenge().as_bytes() != &challenge
    {
        return Err(PublisherIngressError::MalformedRecord);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
