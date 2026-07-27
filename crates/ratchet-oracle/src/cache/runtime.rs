//! Caller-owned evaluator cache runtime substrate.
//!
//! This module ties evaluator observation traces to the in-memory demand graph
//! while keeping evaluator policy decisions explicit at call sites. Callers
//! choose which computations to observe, which memoization subject applies, and
//! which value-hash cost signals are available.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use thiserror::Error;

use super::cutoff::{
    ATTRS_VALUE_HASH_DOMAIN_VERSION, CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION,
    CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION, CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION,
    INLINE_VALUE_HASH_DOMAIN_VERSION, LIST_VALUE_HASH_DOMAIN_VERSION,
    PATH_VALUE_HASH_DOMAIN_VERSION,
};
use super::{
    AttrPositionSourceHash, CacheExprIdentity, CacheableInputFingerprint, DemandCacheKey,
    DemandDependencyGroup, DemandGraph, DemandGraphError, DemandNodeId, DirtyFrontier,
    DurableBlake3Hash, ImpureInputFingerprint, ImpureInputIdentity, ImpureTraceObservation,
    ImpureTraceStatus, MemoizationDecision, MemoizationDemand, MemoizationSubject, NixSha256Digest,
    NodeFreshness, PersistNodeMetadataKey, RecomputeReadyDirty, Reconsideration, UncacheableInput,
    ValueHash, ValueHashError,
};
use crate::attrs::{AttrPosition, repr::AttrSetReprKind};
use crate::string::{ContextElement, ContextKind, NixStringError, StringContext};
use crate::syntax::Span;
use crate::value::Value;

mod derivation_payload;
mod eval_cache;
mod eval_cache_runtime;
mod expression_value;
mod inline_value_payload;

#[allow(unused_imports)]
pub(crate) use derivation_payload::CachedDerivationSidePayloadError;
pub(crate) use derivation_payload::{
    CachedDerivationAtermPath, CachedDerivationOutputPath, CachedDerivationOutputPaths,
    CachedStaticDerivationOutputPathsPayload,
};
use derivation_payload::{DerivationAtermPathRecord, StaticDerivationOutputPathRecord};
pub use eval_cache::EvalCache;
pub use eval_cache_runtime::EvalCacheRuntime;
pub(crate) use expression_value::CachedScalarValue;
pub use expression_value::{CachedAttrEntryWithPosition, CachedExpressionValue};
use inline_value_payload::{
    AttrPayloadEntry, InlineValuePayload, PayloadCursor, PositionedAttrPayloadEntry,
    append_payload_bytes, append_payload_u128, ensure_unique_attr_payload_names,
};
#[cfg(test)]
use inline_value_payload::{append_length_prefixed_payload_bytes, append_payload_byte};

const MAX_CACHED_EXPRESSION_PAYLOAD_NESTING: usize = 64;
const SOURCE_ORDERED_ATTRS_PAYLOAD_TAG: &[u8] = b"attrs-source-order";
const POSITIONED_ATTRS_PAYLOAD_TAG: &[u8] = b"attrs-positioned";
const SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG: &[u8] = b"attrs-source-order-positioned";
const ATTR_REPR_PAYLOAD_ENVELOPE_TAG: &[u8] = b"attrs-repr-v1";
const ATTR_POSITION_SOURCE_PAYLOAD_ENVELOPE_TAG: &[u8] = b"attrs-position-source-v1";
/// A source of evaluator-observed impure input trace entries.
pub trait ImpureInputTraceSource {
    /// Returns impure inputs observed while evaluating a root computation.
    fn impure_input_trace(&self) -> &[ImpureInputFingerprint];

    /// Returns whether the trace is complete enough to be cache-usable.
    fn impure_input_trace_complete(&self) -> bool;
}

/// Recomputes impure-input fingerprints for cached input identities.
pub trait ImpureInputRevalidator {
    /// Revalidates one previously observed cacheable input identity.
    ///
    /// Returning `None` means the input could not be revalidated without
    /// evaluating the original expression, so the cache lookup must miss.
    fn revalidate_impure_input(
        &mut self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint>;
}

/// Whether an observed expression evaluation is eligible for memoization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpressionCacheability {
    /// The expression is cacheable and has a demand-graph node.
    Cacheable(DemandNodeId),
    /// The evaluator could not produce a complete dependency trace.
    Incomplete,
    /// The expression observed an input that makes memoization unsound.
    Uncacheable(UncacheableInput),
}

/// The result of observing one expression evaluation's impure-input trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpressionTraceObservation {
    node: Option<DemandNodeId>,
    trace: ImpureTraceObservation,
    payload_reconsideration: Option<Reconsideration>,
}

/// One clean in-memory expression-payload cache hit.
#[derive(Clone, Debug)]
pub(crate) struct CachedExpressionPayloadHit {
    node: DemandNodeId,
    value: CachedExpressionValue,
    reconsideration: Option<Reconsideration>,
}

/// One clean in-memory derivation ATerm path cache hit.
#[derive(Clone, Debug)]
pub(crate) struct CachedDerivationAtermPathHit {
    node: DemandNodeId,
    path_bytes: Vec<u8>,
    hash_derivation_modulo: Option<NixSha256Digest>,
    reconsideration: Option<Reconsideration>,
}

/// One clean in-memory static derivation output-path cache hit.
#[derive(Clone, Debug)]
pub(crate) struct CachedStaticDerivationOutputPathsHit {
    node: DemandNodeId,
    output_paths: CachedDerivationOutputPaths,
    reconsideration: Option<Reconsideration>,
}

impl ExpressionTraceObservation {
    fn new(node: Option<DemandNodeId>, trace: ImpureTraceObservation) -> Self {
        Self {
            node,
            trace,
            payload_reconsideration: None,
        }
    }

    fn with_payload_reconsideration(
        node: DemandNodeId,
        trace: ImpureTraceObservation,
        payload_reconsideration: Reconsideration,
    ) -> Self {
        Self {
            node: Some(node),
            trace,
            payload_reconsideration: Some(payload_reconsideration),
        }
    }

    /// Returns the expression node wired to cacheable input leaves, if any.
    pub const fn node(&self) -> Option<DemandNodeId> {
        self.node
    }

    /// Returns the observed impure trace cacheability and leaves.
    pub const fn trace(&self) -> &ImpureTraceObservation {
        &self.trace
    }

    /// Returns the value-hash reconsideration from payload observation, if any.
    pub fn payload_reconsideration(&self) -> Option<&Reconsideration> {
        self.payload_reconsideration.as_ref()
    }

    /// Returns whether this expression evaluation can be memoized.
    pub fn cacheability(&self) -> ExpressionCacheability {
        match self.trace.status() {
            ImpureTraceStatus::Cacheable => self
                .node
                .map(ExpressionCacheability::Cacheable)
                .unwrap_or(ExpressionCacheability::Incomplete),
            ImpureTraceStatus::Incomplete => ExpressionCacheability::Incomplete,
            ImpureTraceStatus::Uncacheable(input) => ExpressionCacheability::Uncacheable(input),
        }
    }

    /// Consumes this observation into its node and trace parts.
    pub fn into_parts(self) -> (Option<DemandNodeId>, ImpureTraceObservation) {
        (self.node, self.trace)
    }
}

impl CachedExpressionPayloadHit {
    pub(crate) const fn new(node: DemandNodeId, value: CachedExpressionValue) -> Self {
        Self {
            node,
            value,
            reconsideration: None,
        }
    }

    pub(crate) const fn with_reconsideration(
        node: DemandNodeId,
        value: CachedExpressionValue,
        reconsideration: Reconsideration,
    ) -> Self {
        Self {
            node,
            value,
            reconsideration: Some(reconsideration),
        }
    }

    /// Returns the demand-graph node that supplied this hit.
    pub(crate) const fn node(&self) -> DemandNodeId {
        self.node
    }

    /// Returns the dirty-node reconsideration that admitted this hit, if any.
    pub(crate) fn reconsideration(&self) -> Option<&Reconsideration> {
        self.reconsideration.as_ref()
    }

    /// Consumes the hit into its cached expression payload.
    pub(crate) fn into_value(self) -> CachedExpressionValue {
        self.value
    }
}

impl CachedDerivationAtermPathHit {
    pub(crate) fn new(
        node: DemandNodeId,
        path_bytes: Vec<u8>,
        hash_derivation_modulo: Option<NixSha256Digest>,
    ) -> Self {
        Self {
            node,
            path_bytes,
            hash_derivation_modulo,
            reconsideration: None,
        }
    }

    pub(crate) fn with_reconsideration(
        node: DemandNodeId,
        path_bytes: Vec<u8>,
        hash_derivation_modulo: Option<NixSha256Digest>,
        reconsideration: Reconsideration,
    ) -> Self {
        Self {
            node,
            path_bytes,
            hash_derivation_modulo,
            reconsideration: Some(reconsideration),
        }
    }

    /// Returns the demand-graph node that supplied this hit.
    pub(crate) const fn node(&self) -> DemandNodeId {
        self.node
    }

    /// Returns the value-hash reconsideration used to clean a dirty hit.
    pub(crate) fn reconsideration(&self) -> Option<&Reconsideration> {
        self.reconsideration.as_ref()
    }

    /// Returns the cached derivation hash modulo, if the side record stores it.
    pub(crate) const fn hash_derivation_modulo(&self) -> Option<NixSha256Digest> {
        self.hash_derivation_modulo
    }

    /// Consumes the hit into its cached derivation path bytes.
    pub(crate) fn into_path_bytes(self) -> Vec<u8> {
        self.path_bytes
    }
}

impl CachedStaticDerivationOutputPathsHit {
    pub(crate) const fn new(node: DemandNodeId, output_paths: CachedDerivationOutputPaths) -> Self {
        Self {
            node,
            output_paths,
            reconsideration: None,
        }
    }

    pub(crate) const fn with_reconsideration(
        node: DemandNodeId,
        output_paths: CachedDerivationOutputPaths,
        reconsideration: Reconsideration,
    ) -> Self {
        Self {
            node,
            output_paths,
            reconsideration: Some(reconsideration),
        }
    }

    /// Returns the demand-graph node that supplied this hit.
    pub(crate) const fn node(&self) -> DemandNodeId {
        self.node
    }

    /// Returns the value-hash reconsideration used to clean a dirty hit.
    pub(crate) fn reconsideration(&self) -> Option<&Reconsideration> {
        self.reconsideration.as_ref()
    }

    /// Consumes the hit into its cached static derivation output paths.
    pub(crate) fn into_output_paths(self) -> CachedDerivationOutputPaths {
        self.output_paths
    }
}

/// A same-run memoization demand observation and its admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoizationObservation {
    demand: MemoizationDemand,
    decision: MemoizationDecision,
}

impl MemoizationObservation {
    const fn new(demand: MemoizationDemand, decision: MemoizationDecision) -> Self {
        Self { demand, decision }
    }

    /// Returns the demand count after recording the current demand.
    pub const fn demand(self) -> MemoizationDemand {
        self.demand
    }

    /// Returns the policy decision for the updated demand and caller signals.
    pub const fn decision(self) -> MemoizationDecision {
        self.decision
    }
}

/// Persistent cached-expression payload encoding failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CachedExpressionValuePayloadError {
    /// Payload byte storage could not be reserved.
    #[error("failed to reserve cached expression payload storage for {len} bytes")]
    PayloadAllocationFailed {
        /// The requested byte capacity.
        len: usize,
    },
    /// Payload byte length arithmetic overflowed.
    #[error("cached expression payload length overflow: {current} + {additional}")]
    PayloadLengthOverflow {
        /// The current payload length.
        current: usize,
        /// The additional bytes being appended.
        additional: usize,
    },
    /// Context element storage could not be reserved while decoding.
    #[error("failed to reserve cached expression context storage for {len} elements")]
    ContextAllocationFailed {
        /// The requested context element capacity.
        len: usize,
    },
    /// List element storage could not be reserved while decoding.
    #[error("failed to reserve cached expression list storage for {len} elements")]
    ListAllocationFailed {
        /// The requested list element capacity.
        len: usize,
    },
    /// Attrset binding storage could not be reserved while decoding.
    #[error("failed to reserve cached expression attrset storage for {len} bindings")]
    AttrsAllocationFailed {
        /// The requested attrset binding capacity.
        len: usize,
    },
    /// A length field cannot fit in `usize` on this host.
    #[error("cached expression payload length {len} cannot fit in usize")]
    LengthOverflow {
        /// The oversized encoded length.
        len: u128,
    },
    /// The payload did not carry a known value-hash domain prefix.
    #[error("cached expression payload has an unknown value-hash domain")]
    UnknownDomain,
    /// A payload section had an unexpected tag.
    #[error("cached expression payload has invalid {section} tag {tag}")]
    InvalidTag {
        /// The malformed payload section.
        section: &'static str,
        /// The unexpected tag byte.
        tag: u8,
    },
    /// A decoded bool payload byte was not `0` or `1`.
    #[error("cached expression bool payload has invalid byte {byte}")]
    InvalidBool {
        /// The invalid bool byte.
        byte: u8,
    },
    /// The payload ended before a required section was complete.
    #[error("cached expression payload has {actual} bytes, expected at least {expected}")]
    ShortPayload {
        /// The minimum required payload length.
        expected: usize,
        /// The available payload length.
        actual: usize,
    },
    /// A fixed payload marker was absent at the current cursor position.
    #[error("cached expression payload is missing {marker}")]
    MissingMarker {
        /// The marker name.
        marker: &'static str,
    },
    /// The decoder did not consume the whole payload.
    #[error("cached expression payload has {remaining} trailing bytes")]
    TrailingBytes {
        /// The number of unconsumed bytes.
        remaining: usize,
    },
    /// A decoded string-context element violated context invariants.
    #[error("cached expression payload has invalid string context: {source}")]
    Context {
        /// The underlying string-context error.
        source: NixStringError,
    },
    /// A decoded string-context element was out of canonical order or duplicated.
    #[error("cached expression payload has non-canonical string context element at index {index}")]
    NonCanonicalStringContext {
        /// The zero-based index of the out-of-order or duplicate element.
        index: usize,
    },
    /// A context-bearing payload used the contextual domain with no context elements.
    #[error("cached expression {payload} payload has an empty string context")]
    EmptyStringContext {
        /// The malformed contextual payload kind.
        payload: &'static str,
    },
    /// An attrset payload binding name was out of canonical order or duplicated.
    #[error("cached expression attrset payload has non-canonical binding name at index {index}")]
    NonCanonicalAttrsPayloadName {
        /// The zero-based index of the out-of-order or duplicate binding name.
        index: usize,
    },
    /// A positioned attrset payload used a positioned tag without any positions.
    #[error("cached expression positioned attrset payload has no positioned bindings")]
    PositionlessPositionedAttrsPayload,
    /// A position-source envelope wrapped a payload with no retained positions.
    #[error("cached expression attr-position source envelope has no positioned bindings")]
    PositionSourceWithoutPositions,
    /// A representation envelope wrapped a non-attrset payload.
    #[error("cached expression attr representation envelope has no attrset payload")]
    AttrReprWithoutAttrs,
    /// A representation envelope used a non-canonical wrapper form.
    #[error("cached expression attr representation envelope is non-canonical")]
    NonCanonicalAttrReprEnvelope,
    /// Nested payload decoding exceeded the supported recursion depth.
    #[error("cached expression payload nesting exceeded {limit} levels")]
    PayloadNestingLimitExceeded {
        /// The maximum supported nesting depth.
        limit: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InlineValueRecord {
    payload: InlineValuePayload,
    attr_position_source_hash: Option<AttrPositionSourceHash>,
    value_hash: ValueHash,
    reusable_without_revalidation: bool,
    revalidation_inputs: Option<Vec<CacheableInputFingerprint>>,
}

impl InlineValueRecord {
    fn reusable_without_revalidation(value: CachedExpressionValue) -> Result<Self, ValueHashError> {
        Self::from_cached_value(value, true, None)
    }

    fn requires_revalidation<T>(
        value: CachedExpressionValue,
        source: &T,
    ) -> Result<Self, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        let inputs = cacheable_trace_inputs(source.impure_input_trace())?;
        Self::from_cached_value(value, false, Some(inputs))
            .map_err(|source| DemandGraphError::ValueHash { source })
    }

    fn from_cached_value(
        value: CachedExpressionValue,
        reusable_without_revalidation: bool,
        revalidation_inputs: Option<Vec<CacheableInputFingerprint>>,
    ) -> Result<Self, ValueHashError> {
        let value_hash = value.value_hash()?;
        Ok(Self {
            payload: value.payload,
            attr_position_source_hash: value.attr_position_source_hash,
            value_hash,
            reusable_without_revalidation,
            revalidation_inputs,
        })
    }

    fn value(&self) -> CachedExpressionValue {
        if let Some(source_hash) = self.attr_position_source_hash {
            CachedExpressionValue::from_payload_with_attr_position_source_hash(
                self.payload.clone(),
                source_hash,
            )
        } else {
            CachedExpressionValue::from_payload(self.payload.clone())
        }
    }

    const fn is_reusable_without_revalidation(&self) -> bool {
        self.reusable_without_revalidation
    }

    fn revalidation_inputs(&self) -> Option<&[CacheableInputFingerprint]> {
        self.revalidation_inputs.as_deref()
    }
}

fn cacheable_trace_inputs(
    trace: &[ImpureInputFingerprint],
) -> Result<Vec<CacheableInputFingerprint>, DemandGraphError> {
    let mut inputs = Vec::new();
    inputs.try_reserve_exact(trace.len()).map_err(|_| {
        DemandGraphError::TraceObservationAllocationFailed {
            observations: trace.len(),
        }
    })?;
    for fingerprint in trace {
        let ImpureInputFingerprint::Cacheable(fingerprint) = fingerprint else {
            continue;
        };
        inputs.push(fingerprint.clone());
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrPosition;
    use crate::cache::{
        AttrPositionSourceHash, CacheExprSourceHash, CutoffDecision, DemandCacheKey,
        ImpureTraceStatus, MemoizationDecision, MemoizationDemand, MemoizationSubject,
        NodeFreshness, UncacheableInput,
    };
    use crate::compile::IrId;
    use crate::string::{ContextElement, StringContext};
    use crate::syntax::Span;

    mod derivation_payload;
    mod expression_trace;
    mod inline_payload;
    mod inline_trace_payload;
    mod payload_encoding;
    mod trace_frontier;

    #[derive(Clone, Debug)]
    struct TraceSource {
        trace: Vec<ImpureInputFingerprint>,
        complete: bool,
    }

    impl ImpureInputTraceSource for TraceSource {
        fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
            &self.trace
        }

        fn impure_input_trace_complete(&self) -> bool {
            self.complete
        }
    }

    #[derive(Clone, Debug)]
    struct StaticRevalidator {
        trace: Vec<ImpureInputFingerprint>,
        calls: usize,
    }

    impl StaticRevalidator {
        fn new(trace: Vec<ImpureInputFingerprint>) -> Self {
            Self { trace, calls: 0 }
        }

        const fn calls(&self) -> usize {
            self.calls
        }
    }

    impl ImpureInputRevalidator for StaticRevalidator {
        fn revalidate_impure_input(
            &mut self,
            identity: &ImpureInputIdentity,
        ) -> Option<ImpureInputFingerprint> {
            self.calls = self.calls.saturating_add(1);
            self.trace.iter().find_map(|fingerprint| {
                let cacheable = fingerprint.as_cacheable()?;
                if cacheable.identity() == identity {
                    Some(fingerprint.clone())
                } else {
                    None
                }
            })
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum RecomputeTestError {
        Graph(DemandGraphError),
        Rejected(DemandNodeId),
    }

    impl From<DemandGraphError> for RecomputeTestError {
        fn from(error: DemandGraphError) -> Self {
            Self::Graph(error)
        }
    }

    fn read_file_trace(path: &[u8], contents: &[u8]) -> ImpureInputFingerprint {
        ImpureInputFingerprint::read_file(path, contents).expect("input fingerprints")
    }

    fn value_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn derivation_aterm_hash(aterm: &[u8]) -> ValueHash {
        ValueHash::from_derivation_aterm_bytes(aterm)
    }

    fn expr_source_hash(bytes: &[u8]) -> CacheExprSourceHash {
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn identity(source: &[u8], node: u32) -> CacheExprIdentity {
        CacheExprIdentity::new(expr_source_hash(source), IrId::new(node))
    }

    fn opaque_context(path: &[u8]) -> StringContext {
        StringContext::singleton(
            ContextElement::opaque_path(path.to_vec()).expect("opaque context builds"),
        )
        .expect("context allocates")
    }

    fn all_context_kinds() -> StringContext {
        StringContext::new(vec![
            ContextElement::single_output(b"/nix/store/pkg.drv".to_vec(), b"out".to_vec())
                .expect("single-output context builds"),
            ContextElement::opaque_path(b"/nix/store/source".to_vec())
                .expect("opaque context builds"),
            ContextElement::deep_derivation(b"/nix/store/toolchain.drv".to_vec())
                .expect("deep context builds"),
        ])
    }

    fn context_string_payload_with_opaque_paths(paths: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION)
            .expect("domain appends");
        append_payload_bytes(&mut encoded, b"string").expect("tag appends");
        append_payload_u128(&mut encoded, 0).expect("string length appends");
        append_payload_bytes(&mut encoded, b"context").expect("context tag appends");
        append_payload_u128(&mut encoded, paths.len() as u128).expect("context count appends");
        for path in paths {
            append_payload_byte(&mut encoded, 0).expect("context kind appends");
            append_payload_u128(&mut encoded, path.len() as u128).expect("path length appends");
            append_payload_bytes(&mut encoded, path).expect("path appends");
        }
        encoded
    }

    fn context_path_payload_with_opaque_paths(paths: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION)
            .expect("domain appends");
        append_payload_bytes(&mut encoded, b"path").expect("tag appends");
        append_payload_u128(&mut encoded, 0).expect("path length appends");
        append_payload_bytes(&mut encoded, b"context").expect("context tag appends");
        append_payload_u128(&mut encoded, paths.len() as u128).expect("context count appends");
        for path in paths {
            append_payload_byte(&mut encoded, 0).expect("context kind appends");
            append_payload_u128(&mut encoded, path.len() as u128).expect("path length appends");
            append_payload_bytes(&mut encoded, path).expect("path appends");
        }
        encoded
    }

    fn list_payload_with_len(len: u128) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, LIST_VALUE_HASH_DOMAIN_VERSION).expect("domain appends");
        append_payload_bytes(&mut encoded, b"list").expect("tag appends");
        append_payload_u128(&mut encoded, len).expect("list length appends");
        encoded
    }

    fn attrs_payload_with_len(len: u128) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, ATTRS_VALUE_HASH_DOMAIN_VERSION)
            .expect("domain appends");
        append_payload_bytes(&mut encoded, b"attrs").expect("tag appends");
        append_payload_u128(&mut encoded, len).expect("attrs length appends");
        encoded
    }

    fn key(node: u32, label: &[u8]) -> DemandCacheKey {
        DemandCacheKey::for_free_vars(identity(label, node), [value_hash(label)])
            .expect("key builds")
    }

    #[test]
    fn memoization_demand_admits_conditional_subject_on_second_cheap_demand() {
        let identity = identity(b"source", 1);
        let free_vars = [value_hash(b"captured")];
        let mut cache = EvalCache::new();

        let first = cache
            .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, true)
            .expect("first demand records");
        assert_eq!(first.demand(), MemoizationDemand::new(1));
        assert_eq!(first.decision(), MemoizationDecision::Bypass);
        assert!(
            cache.is_empty(),
            "policy telemetry must not allocate demand-graph nodes"
        );

        let second = cache
            .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, true)
            .expect("second demand records");
        assert_eq!(second.demand(), MemoizationDemand::new(2));
        assert_eq!(second.decision(), MemoizationDecision::Admit);
        assert_eq!(
            cache
                .memoization_demand(identity, free_vars)
                .expect("demand reads"),
            Some(MemoizationDemand::new(2))
        );
        assert!(
            cache.is_empty(),
            "policy telemetry remains separate from expression nodes"
        );
    }

    #[test]
    fn memoization_demand_keeps_conditional_subject_bypassed_when_hash_is_expensive() {
        let identity = identity(b"source", 2);
        let free_vars = [value_hash(b"captured")];
        let mut cache = EvalCache::new();

        cache
            .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, false)
            .expect("first demand records");
        let second = cache
            .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, false)
            .expect("second demand records");

        assert_eq!(second.demand(), MemoizationDemand::new(2));
        assert_eq!(second.decision(), MemoizationDecision::Bypass);
    }

    #[test]
    fn memoization_demand_uses_subject_default_class() {
        let mut cache = EvalCache::new();

        let derivation = cache
            .record_memoization_demand(
                identity(b"drv", 3),
                std::iter::empty::<ValueHash>(),
                MemoizationSubject::DerivationStrict,
                false,
            )
            .expect("always-cache demand records");
        assert_eq!(derivation.demand(), MemoizationDemand::new(1));
        assert_eq!(derivation.decision(), MemoizationDecision::Admit);

        let trivial = cache
            .record_memoization_demand(
                identity(b"trivial", 4),
                std::iter::empty::<ValueHash>(),
                MemoizationSubject::Trivial,
                true,
            )
            .expect("never-cache demand records");
        assert_eq!(trivial.demand(), MemoizationDemand::new(1));
        assert_eq!(trivial.decision(), MemoizationDecision::Bypass);
    }

    #[test]
    fn disabled_runtime_memoization_demand_is_noop() {
        let identity = identity(b"source", 5);
        let free_vars = [value_hash(b"captured")];
        let mut runtime = EvalCacheRuntime::disabled();

        assert_eq!(
            runtime
                .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, true)
                .expect("disabled demand records"),
            None
        );
        assert_eq!(
            runtime
                .memoization_demand(identity, free_vars)
                .expect("disabled demand reads"),
            None
        );
    }

    #[test]
    fn eval_cache_rejects_incomplete_trace_source_without_mutation() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: false,
        };
        let mut cache = EvalCache::new();

        let observation = cache
            .observe_impure_inputs(&source)
            .expect("trace observes");

        assert_eq!(observation.status(), ImpureTraceStatus::Incomplete);
        assert!(observation.leaves().is_empty());
        assert!(cache.is_empty());
    }

    #[test]
    fn eval_cache_rejects_uncacheable_trace_source_without_mutation() {
        let source = TraceSource {
            trace: vec![
                read_file_trace(b"/tmp/version", b"1"),
                ImpureInputFingerprint::current_time(),
            ],
            complete: true,
        };
        let mut cache = EvalCache::new();

        let observation = cache
            .observe_impure_inputs(&source)
            .expect("trace observes");

        assert_eq!(
            observation.status(),
            ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert!(observation.leaves().is_empty());
        assert!(cache.is_empty());
    }
}
