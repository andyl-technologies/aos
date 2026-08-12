//! Content-keyed lambda code references for heap-image snapshots
//! (RFC-0007 doc 31 §1 step 3, increment 1).
//!
//! A lambda's IR is identified in-process by an [`EvalModuleId`] plus pattern and
//! body [`IrId`]s, but a per-process module index is not a durable identity: a
//! restored lambda bound to a drifted module would silently evaluate different
//! code — the `.drv`-divergence failure in a new costume. This module keys a
//! lambda's code by *content* instead: the module's parse-cache source
//! fingerprint ([`CacheExprSourceHash`]) plus the pattern and body node ids, per
//! the persistent-code-cache design. Restore re-resolves the fingerprint to a
//! live module through a [`LambdaCodeResolver`] and **refuses on drift** rather
//! than rebinding.
//!
//! # Wire format
//!
//! ```text
//! lambda-code-ref: fingerprint(32) | pattern(u32) | body(u32)   // 40 bytes
//! ```
//!
//! Alongside the lambda reference, [`CodeNodeRef`] keys a single
//! module-qualified IR node ([`EvalNodeRef`](crate::eval::module::EvalNodeRef)
//! equivalents inside thunk kinds, `with`-scope scrutinees, and flat-capture
//! allocation sites) by the same fingerprint discipline, and the
//! [`LambdaCodeFingerprints`] / [`LambdaCodeResolver`] trait pair carries the
//! module table's code-identity context across the capture/restore boundary.

use thiserror::Error;

use crate::cache::{CacheExprSourceHash, DurableBlake3Hash};
use crate::compile::IrId;
use crate::eval::module::EvalModuleId;

/// Byte length of a serialized [`LambdaCodeRef`]: `fingerprint(32) | pattern(4) |
/// body(4)`.
pub(crate) const LAMBDA_CODE_REF_LEN: usize = 32 + 4 + 4;

/// A durable, drift-checked reference to a lambda's IR.
///
/// Keys code by content — the module source fingerprint plus the pattern and
/// body IR node ids — never by a per-process [`EvalModuleId`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LambdaCodeRef {
    /// The parse-cache source fingerprint of the module owning the lambda's IR.
    pub source_hash: CacheExprSourceHash,
    /// The lambda's argument-pattern IR node.
    pub pattern: IrId,
    /// The lambda's body IR node.
    pub body: IrId,
}

/// A lambda's in-process code coordinates after a successful drift check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedLambdaCode {
    /// The live module the fingerprint re-resolved to.
    pub module: EvalModuleId,
    /// The lambda's argument-pattern IR node.
    pub pattern: IrId,
    /// The lambda's body IR node.
    pub body: IrId,
}

/// Re-resolves a module source fingerprint to a live [`EvalModuleId`].
///
/// Returns `None` when no loaded module carries that fingerprint — the drift
/// signal that makes restore refuse rather than rebind. An ambiguous
/// fingerprint (two live modules with identical identity, which the module
/// table should never produce) must also return `None`: refusing beats
/// guessing between candidates.
pub(crate) trait LambdaCodeResolver {
    /// Resolves `source_hash` to a live module id, or `None` on drift.
    fn resolve(&self, source_hash: CacheExprSourceHash) -> Option<EvalModuleId>;
}

/// Fingerprints live modules for closure capture — the inverse of
/// [`LambdaCodeResolver`].
///
/// Supplied by the `TreeWalk` (which owns the module table) at the capture
/// call site; the `EvalHeap` itself holds no code identity. Returns `None`
/// when a module's identity cannot be fingerprinted, which makes capture
/// refuse the closure rather than emit an unkeyed code reference.
pub(crate) trait LambdaCodeFingerprints {
    /// Returns the content fingerprint of a live module, or `None` when the
    /// module is unknown or unfingerprintable.
    fn fingerprint(&self, module: EvalModuleId) -> Option<CacheExprSourceHash>;

    /// Returns the number of live modules the context fingerprints, so
    /// capture can dump the whole `module id -> fingerprint` table (step-4
    /// W1: raw module ids in attr positions and primop provenance re-resolve
    /// through it at restore).
    fn module_count(&self) -> usize;
}

/// Byte length of a serialized [`CodeNodeRef`]: `fingerprint(32) | node(4)`.
pub(crate) const CODE_NODE_REF_LEN: usize = 32 + 4;

/// A durable, drift-checked reference to one module-qualified IR node.
///
/// The single-node analog of [`LambdaCodeRef`], used for thunk bodies,
/// applied-function and argument nodes, `with`-scope scrutinees, and
/// flat-capture allocation sites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CodeNodeRef {
    /// The parse-cache source fingerprint of the module owning the node.
    pub source_hash: CacheExprSourceHash,
    /// The referenced IR node.
    pub node: IrId,
}

impl CodeNodeRef {
    /// Serializes the reference to its fixed-width little-endian wire form.
    pub(crate) fn to_bytes(self) -> [u8; CODE_NODE_REF_LEN] {
        let mut out = [0u8; CODE_NODE_REF_LEN];
        out[0..32].copy_from_slice(&self.source_hash.as_durable_hash().as_bytes());
        out[32..36].copy_from_slice(&self.node.as_u32().to_le_bytes());
        out
    }

    /// Parses a reference at `*cursor`, advancing it past the fixed-width record.
    ///
    /// # Errors
    ///
    /// Returns [`LambdaCodeDrift::Malformed`] when fewer than
    /// [`CODE_NODE_REF_LEN`] bytes remain at `*cursor`.
    pub(crate) fn read(bytes: &[u8], cursor: &mut usize) -> Result<Self, LambdaCodeDrift> {
        let end = cursor
            .checked_add(CODE_NODE_REF_LEN)
            .ok_or(LambdaCodeDrift::Malformed)?;
        let slice = bytes.get(*cursor..end).ok_or(LambdaCodeDrift::Malformed)?;
        let fingerprint: [u8; 32] = slice[0..32]
            .try_into()
            .map_err(|_| LambdaCodeDrift::Malformed)?;
        let node = IrId::new(u32::from_le_bytes(
            slice[32..36]
                .try_into()
                .map_err(|_| LambdaCodeDrift::Malformed)?,
        ));
        *cursor = end;
        Ok(Self {
            source_hash: CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::from_bytes(
                fingerprint,
            )),
            node,
        })
    }

    /// Resolves the reference against `resolver`, refusing on source drift.
    ///
    /// # Errors
    ///
    /// Returns [`LambdaCodeDrift::SourceMissing`] when the fingerprint is absent
    /// from the current evaluator.
    pub(crate) fn resolve(
        self,
        resolver: &dyn LambdaCodeResolver,
    ) -> Result<(EvalModuleId, IrId), LambdaCodeDrift> {
        let module = resolver
            .resolve(self.source_hash)
            .ok_or(LambdaCodeDrift::SourceMissing)?;
        Ok((module, self.node))
    }
}

impl LambdaCodeRef {
    /// Serializes the reference to its fixed-width little-endian wire form.
    pub(crate) fn to_bytes(self) -> [u8; LAMBDA_CODE_REF_LEN] {
        let mut out = [0u8; LAMBDA_CODE_REF_LEN];
        out[0..32].copy_from_slice(&self.source_hash.as_durable_hash().as_bytes());
        out[32..36].copy_from_slice(&self.pattern.as_u32().to_le_bytes());
        out[36..40].copy_from_slice(&self.body.as_u32().to_le_bytes());
        out
    }

    /// Parses a reference at `*cursor`, advancing it past the fixed-width record.
    ///
    /// # Errors
    ///
    /// Returns [`LambdaCodeDrift::Malformed`] when fewer than
    /// [`LAMBDA_CODE_REF_LEN`] bytes remain at `*cursor`.
    pub(crate) fn read(bytes: &[u8], cursor: &mut usize) -> Result<Self, LambdaCodeDrift> {
        let end = cursor
            .checked_add(LAMBDA_CODE_REF_LEN)
            .ok_or(LambdaCodeDrift::Malformed)?;
        let slice = bytes.get(*cursor..end).ok_or(LambdaCodeDrift::Malformed)?;
        let fingerprint: [u8; 32] = slice[0..32]
            .try_into()
            .map_err(|_| LambdaCodeDrift::Malformed)?;
        let pattern = IrId::new(u32::from_le_bytes(
            slice[32..36]
                .try_into()
                .map_err(|_| LambdaCodeDrift::Malformed)?,
        ));
        let body = IrId::new(u32::from_le_bytes(
            slice[36..40]
                .try_into()
                .map_err(|_| LambdaCodeDrift::Malformed)?,
        ));
        *cursor = end;
        Ok(Self {
            source_hash: CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::from_bytes(
                fingerprint,
            )),
            pattern,
            body,
        })
    }

    /// Resolves the reference against `resolver`, refusing on source drift.
    ///
    /// # Errors
    ///
    /// Returns [`LambdaCodeDrift::SourceMissing`] when the fingerprint is absent
    /// from the current evaluator (the module's IR changed or is not loaded).
    pub(crate) fn resolve(
        self,
        resolver: &dyn LambdaCodeResolver,
    ) -> Result<ResolvedLambdaCode, LambdaCodeDrift> {
        let module = resolver
            .resolve(self.source_hash)
            .ok_or(LambdaCodeDrift::SourceMissing)?;
        Ok(ResolvedLambdaCode {
            module,
            pattern: self.pattern,
            body: self.body,
        })
    }
}

/// A restored lambda's code reference could not be bound to current IR.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum LambdaCodeDrift {
    /// The reference bytes were truncated or otherwise unparseable.
    #[error("lambda code reference is malformed")]
    Malformed,
    /// No loaded module carries the reference's source fingerprint (IR drift).
    #[error("lambda code source fingerprint is absent from the current evaluator")]
    SourceMissing,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_hash(byte: u8) -> CacheExprSourceHash {
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::from_bytes([byte; 32]))
    }

    /// A resolver that knows exactly one fingerprint, mapping it to a module.
    struct OneModule {
        known: CacheExprSourceHash,
        module: EvalModuleId,
    }

    impl LambdaCodeResolver for OneModule {
        fn resolve(&self, source_hash: CacheExprSourceHash) -> Option<EvalModuleId> {
            (source_hash == self.known).then_some(self.module)
        }
    }

    #[test]
    fn code_ref_round_trips_through_bytes() {
        let code_ref = LambdaCodeRef {
            source_hash: source_hash(0xab),
            pattern: IrId::new(7),
            body: IrId::new(42),
        };
        let bytes = code_ref.to_bytes();
        let mut cursor = 0;
        let parsed = LambdaCodeRef::read(&bytes, &mut cursor).expect("parses");
        assert_eq!(parsed, code_ref);
        assert_eq!(cursor, LAMBDA_CODE_REF_LEN);
    }

    #[test]
    fn resolve_binds_a_matching_fingerprint() {
        let module = EvalModuleId::new(3);
        let resolver = OneModule {
            known: source_hash(0x11),
            module,
        };
        let resolved = LambdaCodeRef {
            source_hash: source_hash(0x11),
            pattern: IrId::new(1),
            body: IrId::new(2),
        }
        .resolve(&resolver)
        .expect("matching fingerprint resolves");
        assert_eq!(
            resolved,
            ResolvedLambdaCode {
                module,
                pattern: IrId::new(1),
                body: IrId::new(2),
            }
        );
    }

    #[test]
    fn resolve_refuses_a_drifted_fingerprint() {
        let resolver = OneModule {
            known: source_hash(0x11),
            module: EvalModuleId::new(3),
        };
        // A fingerprint the resolver does not know is drift, not a silent rebind.
        let drift = LambdaCodeRef {
            source_hash: source_hash(0x22),
            pattern: IrId::new(1),
            body: IrId::new(2),
        }
        .resolve(&resolver);
        assert_eq!(drift, Err(LambdaCodeDrift::SourceMissing));
    }

    #[test]
    fn read_refuses_truncated_bytes() {
        let bytes = [0u8; LAMBDA_CODE_REF_LEN - 1];
        let mut cursor = 0;
        assert_eq!(
            LambdaCodeRef::read(&bytes, &mut cursor),
            Err(LambdaCodeDrift::Malformed)
        );
    }
}
