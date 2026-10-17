//! Finite original construction callback cuts, without readiness authority.
//!
//! ```text
//! version:u32=1 | summary_bytes:u32=120 | row_count:u32 | flags:u32=0
//! hold_generation:u64 | prepared_scope_hash[32] | initialization_commitment[32]
//! original_cut_sha256[32]
//! row[row_count]: class:u32 | flags:u32=0 | callback_id:u64
//!                 arm_generation:u64 | context_id:u64
//! ```
//!
//! Public scalars are big endian. SHA-256 separately covers the source-defined
//! tagged little-endian preimage. Numeric callback/context identities contain
//! no pointers and grant no permission to dispatch a callback.

use std::collections::BTreeSet;

use crucible_node_contract::U64;
use sha2::{Digest, Sha256};

use super::initialization::{NATIVE_INITIALIZATION_MAX_CALLBACKS, NativeInitializationPreparation};
use super::{NativeCommandError, codec::Cursor};

/// Selects one installed, source-specific construction callback class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NativeInitializationClass {
    /// Starts the original QMP dispatcher only with no realized monitor inputs.
    QmpDispatcherStartup = 1,
    /// Dispatches an original empty coroutine notification after native checks.
    EmptyCoroutineNotification = 2,
    /// Dispatches an original IDE restart with no error or modeled pending work.
    IdeZeroErrorRestart = 4,
}

/// Names one actual original callback arm within a finite native cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeInitializationRow {
    /// Selects the native class and its mandatory installed source predicates.
    pub class: NativeInitializationClass,
    /// Names the original process-local callback object.
    pub callback_id: U64,
    /// Distinguishes the original pending arm from later rearming of that object.
    pub arm_generation: U64,
    /// Names the original process-local owner context.
    pub context_id: U64,
}

/// Retains a complete original source-selected construction cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeInitializationCut {
    /// Names the genuine retained admission HOLD lifetime.
    pub hold_generation: U64,
    /// Binds the original native preparation scope.
    pub prepared_scope_hash: [u8; 32],
    /// Binds all launch-pinned original construction authorization fields.
    pub initialization_commitment: [u8; 32],
    /// Identifies this immutable native cut, independently of its HOLD lifetime.
    pub original_cut_digest: [u8; 32],
    /// Preserves original native callback order, including an authentic empty cut.
    pub rows: Vec<NativeInitializationRow>,
}

impl NativeInitializationCut {
    fn validate_rows(&self) -> Result<(), NativeCommandError> {
        if self.rows.len() > NATIVE_INITIALIZATION_MAX_CALLBACKS as usize {
            return Err(NativeCommandError::ResourceLimit);
        }
        if self.hold_generation.get() == 0
            || self.prepared_scope_hash == [0; 32]
            || self.initialization_commitment == [0; 32]
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut callbacks = BTreeSet::new();
        for row in &self.rows {
            if row.callback_id.get() == 0
                || row.arm_generation.get() == 0
                || row.arm_generation.get() == u64::MAX
                || row.context_id.get() == 0
                || !callbacks.insert(row.callback_id)
            {
                return Err(NativeCommandError::Conflict);
            }
        }
        Ok(())
    }

    /// Recomputes the source-defined SHA-256 identity of the ordered cut.
    ///
    /// This verifies byte integrity only; callers must compare the original
    /// authentic source result rather than adopt an externally constructed cut.
    ///
    /// # Errors
    /// Rejects invalid identities, callback arms, duplicates or excessive rows.
    pub fn computed_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        self.validate_rows()?;
        let mut hash = Sha256::new();
        hash.update(b"crucible.qemu-native-initialization-cut.v1\0");
        hash.update(self.prepared_scope_hash);
        hash.update(self.initialization_commitment);
        hash.update(self.hold_generation.get().to_le_bytes());
        hash.update((self.rows.len() as u32).to_le_bytes());
        for row in &self.rows {
            hash.update((row.class as u32).to_le_bytes());
            hash.update(0u32.to_le_bytes());
            hash.update(row.callback_id.get().to_le_bytes());
            hash.update(row.arm_generation.get().to_le_bytes());
            hash.update(row.context_id.get().to_le_bytes());
        }
        Ok(hash.finalize().into())
    }

    /// Validates the complete bounded cut without authorizing callback execution.
    ///
    /// # Errors
    /// Rejects an invalid row set or a changed original native cut digest.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.computed_digest()? != self.original_cut_digest {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Checks the cut against the complete originally pinned preparation data.
    ///
    /// Equality is a correlation check, never proof of native custody or readiness.
    ///
    /// # Errors
    /// Rejects changed scope, policy commitment, unenrolled classes, excessive
    /// callback count, or invalid cut integrity.
    pub fn validate_against(
        &self,
        preparation: &NativeInitializationPreparation,
    ) -> Result<(), NativeCommandError> {
        self.validate()?;
        if self.prepared_scope_hash != preparation.preparation.scope.identity_digest()?
            || self.initialization_commitment != preparation.identity_digest()?
            || self.rows.len() > preparation.maximum_callbacks as usize
            || self
                .rows
                .iter()
                .any(|row| preparation.class_mask & row.class as u32 == 0)
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes exactly this immutable original cut in portable big-endian bytes.
    ///
    /// # Errors
    /// Rejects any cut that fails [`Self::validate`].
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(120 + self.rows.len() * 32);
        for value in [1, 120, self.rows.len() as u32, 0] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.hold_generation.get().to_be_bytes());
        bytes.extend_from_slice(&self.prepared_scope_hash);
        bytes.extend_from_slice(&self.initialization_commitment);
        bytes.extend_from_slice(&self.original_cut_digest);
        for row in &self.rows {
            bytes.extend_from_slice(&(row.class as u32).to_be_bytes());
            bytes.extend_from_slice(&0u32.to_be_bytes());
            bytes.extend_from_slice(&row.callback_id.get().to_be_bytes());
            bytes.extend_from_slice(&row.arm_generation.get().to_be_bytes());
            bytes.extend_from_slice(&row.context_id.get().to_be_bytes());
        }
        Ok(bytes)
    }

    /// Decodes a complete bounded cut, checking counts before allocating rows.
    ///
    /// # Errors
    /// Rejects invalid prefixes, open classes or flags, malformed lengths,
    /// excessive rows, changed cut hashes or invalid original arm identities.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != 120 {
            return Err(NativeCommandError::Invalid("initialization cut format"));
        }
        let count = cursor.u32()? as usize;
        if count > NATIVE_INITIALIZATION_MAX_CALLBACKS as usize {
            return Err(NativeCommandError::ResourceLimit);
        }
        if cursor.u32()? != 0 || bytes.len() != 120 + count * 32 {
            return Err(NativeCommandError::Invalid(
                "initialization cut length/flags",
            ));
        }
        let hold_generation = U64::new(cursor.u64()?);
        let prepared_scope_hash = cursor.array()?;
        let initialization_commitment = cursor.array()?;
        let original_cut_digest = cursor.array()?;
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            let class = match cursor.u32()? {
                1 => NativeInitializationClass::QmpDispatcherStartup,
                2 => NativeInitializationClass::EmptyCoroutineNotification,
                4 => NativeInitializationClass::IdeZeroErrorRestart,
                _ => return Err(NativeCommandError::Invalid("initialization class")),
            };
            if cursor.u32()? != 0 {
                return Err(NativeCommandError::Invalid("initialization row flags"));
            }
            rows.push(NativeInitializationRow {
                class,
                callback_id: U64::new(cursor.u64()?),
                arm_generation: U64::new(cursor.u64()?),
                context_id: U64::new(cursor.u64()?),
            });
        }
        let result = Self {
            hold_generation,
            prepared_scope_hash,
            initialization_commitment,
            original_cut_digest,
            rows,
        };
        result.validate()?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "initialization_cut_tests.rs"]
mod tests;
