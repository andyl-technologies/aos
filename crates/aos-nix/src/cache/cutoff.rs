//! Early-cutoff decisions for incremental evaluation.
//!
//! The demand graph owns invalidation and dependency propagation. This module
//! owns the red/green decision at one reconsidered node: if recomputation
//! produces the same value hash as the previous run, the caller can stop
//! propagation at that node; otherwise the caller must propagate to consumers.

use super::hashing::DurableBlake3Hash;

/// A durable hash of a canonical evaluated value.
///
/// The future value serializer computes this as `blake3(canonical(value))`.
/// This wrapper gives cutoff decisions a distinct semantic type before the full
/// value store exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValueHash(DurableBlake3Hash);

impl ValueHash {
    /// Wraps a durable BLAKE3 hash produced from a canonical value.
    pub const fn from_canonical_value_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Wraps a durable BLAKE3 hash of an impure input observation.
    ///
    /// This constructor is for demand-graph leaf nodes whose "value" is an
    /// observed filesystem or environment result, not a canonical Nix value.
    pub const fn from_impure_input_observation_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }
}

/// The propagation decision for one reconsidered cache node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CutoffDecision {
    /// The recomputed value hash matched the previous value hash.
    CutOff,
    /// The node has no previous value hash or recomputed to a different hash.
    Propagate,
}

impl CutoffDecision {
    /// Returns whether consumers of the reconsidered node must be dirtied.
    pub const fn should_propagate(self) -> bool {
        matches!(self, Self::Propagate)
    }
}

/// Stateless early-cutoff decision logic.
#[derive(Clone, Copy, Debug, Default)]
pub struct EarlyCutoff;

impl EarlyCutoff {
    /// Compares the previous and recomputed value hashes for one node.
    pub fn decide(previous: Option<ValueHash>, recomputed: ValueHash) -> CutoffDecision {
        match previous {
            Some(previous) if previous == recomputed => CutoffDecision::CutOff,
            Some(_) | None => CutoffDecision::Propagate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn input_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_impure_input_observation_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    #[test]
    fn impure_input_observation_hashes_participate_in_cutoff_decisions() {
        let hash = input_hash(b"same input result");
        let decision = EarlyCutoff::decide(Some(hash), hash);

        assert_eq!(decision, CutoffDecision::CutOff);
    }

    #[test]
    fn unchanged_value_hash_cuts_off_propagation() {
        let hash = value_hash(b"same value");
        let decision = EarlyCutoff::decide(Some(hash), hash);

        assert_eq!(decision, CutoffDecision::CutOff);
        assert!(!decision.should_propagate());
    }

    #[test]
    fn changed_value_hash_propagates_to_consumers() {
        let decision = EarlyCutoff::decide(
            Some(value_hash(b"old value")),
            value_hash(b"recomputed value"),
        );

        assert_eq!(decision, CutoffDecision::Propagate);
        assert!(decision.should_propagate());
    }

    #[test]
    fn missing_previous_hash_propagates_to_consumers() {
        let decision = EarlyCutoff::decide(None, value_hash(b"first value"));

        assert_eq!(decision, CutoffDecision::Propagate);
        assert!(decision.should_propagate());
    }
}
