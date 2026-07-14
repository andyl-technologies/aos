//! Code-identity context for heap-image closure capture/restore (RFC-0007
//! doc 31 §1 step 3).
//!
//! The closure serializer keys code by content — a module's identity hash —
//! never by per-process [`EvalModuleId`]. The [`EvalHeap`] holds no module
//! table, so the `TreeWalk` supplies the context at the capture/restore call
//! site: [`TreeWalk::snapshot_code_identity`] snapshots every live module's
//! fingerprint into an owned, heap-independent table that serves both
//! directions — fingerprinting at capture ([`LambdaCodeFingerprints`]) and
//! refuse-on-drift resolution at restore ([`LambdaCodeResolver`]).
//!
//! The snapshot is owned (no borrow of the evaluator), so an in-process
//! restore can drop or swap the evaluator's heap between capture and restore
//! while keeping the same identity table.
//!
//! [`EvalHeap`]: crate::eval::heap::EvalHeap

use std::collections::HashMap;

use crate::cache::CacheExprSourceHash;
use crate::eval::heap::{LambdaCodeFingerprints, LambdaCodeResolver};
use crate::eval::module::EvalModuleId;

use super::super::TreeWalk;

/// An owned snapshot of every live module's content fingerprint.
///
/// Produced by [`TreeWalk::snapshot_code_identity`]; serves as both the
/// capture-side [`LambdaCodeFingerprints`] context and the restore-side
/// [`LambdaCodeResolver`]. Two live modules *can* carry one fingerprint (the
/// same file loaded again under a scoped import, for example); the identity
/// hash is the parse-cache key domain, so an equal hash means equal source
/// identity and therefore equal deterministic lowered IR — resolution binds
/// the first such module, which is not a rebind to different code. Refusal is
/// reserved for fingerprints absent from the table (genuine drift).
#[derive(Debug)]
pub(crate) struct TreeWalkCodeIdentity {
    /// Per-module fingerprints, indexed by module id.
    fingerprints: Vec<Option<CacheExprSourceHash>>,
    /// Reverse map to the first module carrying each fingerprint.
    modules_by_fingerprint: HashMap<CacheExprSourceHash, EvalModuleId>,
}

impl LambdaCodeFingerprints for TreeWalkCodeIdentity {
    fn fingerprint(&self, module: EvalModuleId) -> Option<CacheExprSourceHash> {
        self.fingerprints.get(module.index()).copied().flatten()
    }
}

impl LambdaCodeResolver for TreeWalkCodeIdentity {
    fn resolve(&self, source_hash: CacheExprSourceHash) -> Option<EvalModuleId> {
        self.modules_by_fingerprint.get(&source_hash).copied()
    }
}

impl TreeWalk {
    /// Snapshots the module table's code-identity context for heap-image
    /// closure capture and restore.
    ///
    /// Fingerprints every live module by its cache identity hash (source name
    /// and bytes for source-backed modules, the lowered-IR fingerprint
    /// otherwise). Modules whose identity cannot be hashed stay
    /// unfingerprintable, which makes capture refuse their closures rather
    /// than emit unkeyed code references.
    pub(crate) fn snapshot_code_identity(&self) -> TreeWalkCodeIdentity {
        let mut fingerprints = Vec::with_capacity(self.modules.len());
        let mut modules_by_fingerprint: HashMap<CacheExprSourceHash, EvalModuleId> =
            HashMap::with_capacity(self.modules.len());
        for (index, module) in self.modules.iter().enumerate() {
            let fingerprint = Self::cache_module_identity_hash(module)
                .map(CacheExprSourceHash::from_durable_hash);
            if let Some(fingerprint) = fingerprint {
                // First module wins for a repeated fingerprint: equal identity
                // hashes mean equal source identity and equal deterministic
                // lowered IR (see the type docs), so this is never a rebind to
                // different code.
                modules_by_fingerprint
                    .entry(fingerprint)
                    .or_insert(EvalModuleId::new(index as u32));
            }
            fingerprints.push(fingerprint);
        }
        TreeWalkCodeIdentity {
            fingerprints,
            modules_by_fingerprint,
        }
    }
}
