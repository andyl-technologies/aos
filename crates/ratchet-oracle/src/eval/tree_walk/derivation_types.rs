//! Derivation hashing, CA-output, and materialization report types
//! (split from tree_walk.rs under the §2 file-size cap).
use super::*;

/// Reports cold hash-consed values ensured in the indexed persistent value pack.
///
/// This is an explicit out-of-core spill precursor report. It describes cold
/// permanent values that were captured as replayable force-cache payloads and
/// made addressable in the persistent cache's indexed `values/` pack. It does
/// not imply that evaluator heap records were evicted or replaced with
/// content-hash handles.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColdHashConsedValueMaterializationReport {
    pub(crate) candidates: usize,
    pub(crate) candidate_bytes: usize,
    pub(crate) captured: usize,
    pub(crate) uncapturable: usize,
    pub(crate) materialized: usize,
    pub(crate) skipped: usize,
    pub(crate) errors: usize,
    pub(crate) cache_unavailable: usize,
    pub(crate) persistent_payload_bytes: u128,
    pub(crate) materialized_hashes: Vec<ValueHash>,
}

impl ColdHashConsedValueMaterializationReport {
    pub(crate) fn record_candidates(&mut self, values: &[EvalHeapColdHashConsedValue]) {
        self.candidates = values.len();
        self.candidate_bytes = values.iter().fold(0usize, |bytes, value| {
            bytes.saturating_add(value.size_bytes())
        });
    }

    pub(crate) fn record_captured(&mut self, payload: &CachedExpressionValue) {
        self.captured = self.captured.saturating_add(1);
        self.persistent_payload_bytes = self
            .persistent_payload_bytes
            .saturating_add(payload.persistent_payload_len());
    }

    pub(crate) fn record_materialized(&mut self, value_hash: ValueHash) {
        self.materialized = self.materialized.saturating_add(1);
        self.materialized_hashes.push(value_hash);
    }

    /// Returns the number of cold hash-consed records selected before capture.
    pub const fn candidates(&self) -> usize {
        self.candidates
    }

    /// Returns the logical allocation bytes covered by selected candidates.
    pub const fn candidate_bytes(&self) -> usize {
        self.candidate_bytes
    }

    /// Returns the number of candidates captured as replayable value payloads.
    pub const fn captured(&self) -> usize {
        self.captured
    }

    /// Returns the number of candidates that could not be captured.
    pub const fn uncapturable(&self) -> usize {
        self.uncapturable
    }

    /// Returns the number of captured payloads ensured in the indexed value pack.
    pub const fn materialized(&self) -> usize {
        self.materialized
    }

    /// Returns the number of captured payloads skipped by the materializer.
    pub const fn skipped(&self) -> usize {
        self.skipped
    }

    /// Returns the number of snapshot, hashing, or write errors observed.
    pub const fn errors(&self) -> usize {
        self.errors
    }

    /// Returns the number of candidates skipped because no persistent cache opened.
    pub const fn cache_unavailable(&self) -> usize {
        self.cache_unavailable
    }

    /// Returns the replayable payload bytes represented by captured candidates.
    pub const fn persistent_payload_bytes(&self) -> u128 {
        self.persistent_payload_bytes
    }

    /// Returns the value hashes ensured in the indexed value pack.
    pub fn materialized_hashes(&self) -> &[ValueHash] {
        &self.materialized_hashes
    }
}

/// The *derivation hash modulo* (`hashDerivationModulo`) of a derivation.
///
/// Nix derivation/store identity rests on three distinct SHA-256 values that are
/// easy to conflate when all are bare `[u8; 32]`: the derivation-hash-modulo (the
/// recursive ATerm-with-input-substitution hash that seeds input-addressed output
/// paths), the raw `.drv` ATerm hash, and an output/content-address digest. This
/// newtype carries only a [`NixSha256Digest`] and exposes named accessors at the
/// serialization/output-path boundary so internal BLAKE3 cache hashes cannot be
/// passed as derivation modulo hashes without an explicit domain conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DerivationHashModulo(NixSha256Digest);

impl DerivationHashModulo {
    pub(crate) fn from_nix_sha256_digest(digest: NixSha256Digest) -> Self {
        Self(digest)
    }

    #[cfg(test)]
    pub(crate) fn from_sha256_bytes(bytes: [u8; 32]) -> Self {
        Self::from_nix_sha256_digest(NixSha256Digest::from_bytes(bytes))
    }

    pub(crate) const fn nix_sha256_digest(self) -> NixSha256Digest {
        self.0
    }
}

#[derive(Clone, Debug)]
pub(crate) struct KnownDerivation {
    pub(crate) id: IrId,
    pub(crate) span: Span,
    pub(crate) derivation: nix_compat::derivation::Derivation,
    pub(crate) hash_derivation_modulo: DerivationHashModulo,
    pub(crate) output_names: BTreeSet<String>,
    pub(crate) output_resolution: DerivationOutputResolution,
    pub(crate) aterm_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(crate) struct KnownDerivationInputHashes {
    pub(crate) hashes: BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
    pub(crate) has_deferred: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DerivationOutputResolution {
    StaticPaths,
    FloatingCa(FloatingCaOutput),
    Impure(FloatingCaOutput),
    DeferredPlaceholders,
}

impl DerivationOutputResolution {
    pub(crate) fn has_deferred_outputs(self) -> bool {
        !matches!(self, Self::StaticPaths)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FloatingCaOutput {
    pub(crate) method: FloatingCaMethod,
    pub(crate) hash_algo: nix_compat::nixhash::HashAlgo,
}

impl FloatingCaOutput {
    pub(crate) fn aterm_hash_algo(self) -> String {
        let mut algo = String::new();
        if matches!(self.method, FloatingCaMethod::Recursive) {
            algo.push_str("r:");
        }
        algo.push_str(&self.hash_algo.to_string());
        algo
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FloatingCaMethod {
    Flat,
    Recursive,
}

#[derive(Debug)]
pub(crate) struct StructuredAttrsJson {
    pub(crate) bytes: Vec<u8>,
    pub(crate) has_fields: bool,
}

impl StructuredAttrsJson {
    pub(crate) fn new() -> Self {
        Self {
            bytes: b"{".to_vec(),
            has_fields: false,
        }
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.bytes.push(b'}');
        self.bytes
    }
}
