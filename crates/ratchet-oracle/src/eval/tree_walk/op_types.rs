//! Operator, equality, hash-format, and builtin-arity support types for evaluation.

use super::*;

pub(crate) fn dir_name_range(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    if bytes[bytes.len() - 1] == b'/' {
        let mut end = bytes.len();
        while end > 1 && bytes[end - 1] == b'/' && bytes[..end - 1].iter().any(|byte| *byte != b'/')
        {
            end -= 1;
        }
        return Some((0, end));
    }
    let slash = bytes.iter().rposition(|byte| *byte == b'/')?;
    let mut end = slash + 1;
    while end > 1 && bytes[end - 1] == b'/' && bytes[..end].iter().any(|byte| *byte != b'/') {
        end -= 1;
    }
    Some((0, end))
}

pub(crate) fn context_free_dot_string(id: IrId, span: Span) -> Result<NixString, TreeWalkError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(1).map_err(|_| {
        TreeWalkError::new(
            TreeWalkErrorKind::String {
                id,
                source: NixStringError::ByteAllocationFailed { len: 1 },
            },
            span,
        )
    })?;
    bytes.push(b'.');
    Ok(NixString::from_bytes(bytes))
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Number {
    Int(i64),
    Float(f64),
}

#[derive(Debug)]
pub(crate) struct ReflectedContextGroup {
    pub(crate) path: Vec<u8>,
    pub(crate) path_flag: bool,
    pub(crate) all_outputs: bool,
    pub(crate) outputs: Vec<Vec<u8>>,
}

impl ReflectedContextGroup {
    pub(crate) fn new(path: Vec<u8>) -> Self {
        Self {
            path,
            path_flag: false,
            all_outputs: false,
            outputs: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DynamicAttrNullPolicy {
    SkipNull,
    RejectNull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EqualityContext {
    Direct,
    Nested,
}

#[derive(Debug)]
pub(crate) struct ReplaceStringPattern {
    pub(crate) from: Vec<u8>,
    pub(crate) replacement: Value,
}

#[derive(Debug)]
pub(crate) struct ReplaceStringReplacement {
    pub(crate) bytes: Vec<u8>,
    pub(crate) context: StringContext,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SourcePathFilter {
    pub(crate) function: Value,
    pub(crate) id: IrId,
    pub(crate) span: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HashStringAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashStringAlgorithm {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"md5" => Some(Self::Md5),
            b"sha1" => Some(Self::Sha1),
            b"sha256" => Some(Self::Sha256),
            b"sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static [u8] {
        match self {
            Self::Md5 => b"md5",
            Self::Sha1 => b"sha1",
            Self::Sha256 => b"sha256",
            Self::Sha512 => b"sha512",
        }
    }

    pub(crate) fn digest_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// A Nix-observed hash digest paired with the algorithm that defines its length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NixHashDigest {
    algorithm: HashStringAlgorithm,
    bytes: Vec<u8>,
}

impl NixHashDigest {
    /// Wraps digest bytes after confirming they match `algorithm`.
    pub(crate) fn new(algorithm: HashStringAlgorithm, bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() == algorithm.digest_len() {
            Some(Self { algorithm, bytes })
        } else {
            None
        }
    }

    /// Wraps a SHA-256 digest already tagged as a Nix store/hash digest.
    pub(crate) fn from_nix_sha256(digest: NixSha256Digest) -> Self {
        Self {
            algorithm: HashStringAlgorithm::Sha256,
            bytes: digest.as_bytes().to_vec(),
        }
    }

    /// Returns the algorithm that defines the digest length and encoding tag.
    pub(crate) const fn algorithm(&self) -> HashStringAlgorithm {
        self.algorithm
    }

    /// Returns the raw Nix-observed digest bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the digest as a Nix SHA-256 value when its algorithm permits it.
    pub(crate) fn as_nix_sha256(&self) -> Option<NixSha256Digest> {
        if self.algorithm != HashStringAlgorithm::Sha256 || self.bytes.len() != 32 {
            return None;
        }
        let mut fixed = [0_u8; 32];
        fixed.copy_from_slice(&self.bytes);
        Some(NixSha256Digest::from_bytes(fixed))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConvertHashFormat {
    Base16,
    Nix32,
    Base64,
    Sri,
}

impl ConvertHashFormat {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"base16" => Some(Self::Base16),
            b"nix32" | b"base32" => Some(Self::Nix32),
            b"base64" => Some(Self::Base64),
            b"sri" => Some(Self::Sri),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConvertHashInputFormat {
    Sri,
    Typed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nix_hash_digest_tracks_algorithm_and_sha256_domain() {
        let sha256 = NixSha256Digest::from_bytes([7; 32]);
        let digest = NixHashDigest::from_nix_sha256(sha256);

        assert_eq!(digest.algorithm(), HashStringAlgorithm::Sha256);
        assert_eq!(digest.bytes(), &[7; 32]);
        assert_eq!(digest.as_nix_sha256(), Some(sha256));

        let md5 = NixHashDigest::new(HashStringAlgorithm::Md5, vec![3; 16])
            .expect("md5 digest has the expected length");
        assert_eq!(md5.algorithm(), HashStringAlgorithm::Md5);
        assert_eq!(md5.bytes(), &[3; 16]);
        assert_eq!(md5.as_nix_sha256(), None);
    }

    #[test]
    fn nix_hash_digest_rejects_wrong_algorithm_length() {
        assert_eq!(
            NixHashDigest::new(HashStringAlgorithm::Sha1, vec![0; 32]),
            None
        );
        assert_eq!(
            NixHashDigest::new(HashStringAlgorithm::Sha256, vec![0; 20]),
            None
        );
    }
}

pub(crate) fn unsupported_primop(call: BuiltinCall) -> Result<Value, TreeWalkError> {
    Err(TreeWalkError::new(
        TreeWalkErrorKind::UnsupportedPrimOp {
            id: call.id,
            symbol: call.symbol,
        },
        call.span,
    ))
}

pub(crate) fn unsupported_builtin_attr(
    id: IrId,
    span: Span,
    symbol: Symbol,
) -> Result<Value, TreeWalkError> {
    Err(TreeWalkError::new(
        TreeWalkErrorKind::UnsupportedBuiltinAttr { id, symbol },
        span,
    ))
}

pub(crate) fn check_builtin_apply_arity(
    call: BuiltinCall,
    builtin: Builtin,
    actual: usize,
) -> Result<(), TreeWalkError> {
    let Some(expected) = builtin.first_class_arity() else {
        return Err(TreeWalkError::new(
            TreeWalkErrorKind::UnsupportedPrimOp {
                id: call.id,
                symbol: call.symbol,
            },
            call.span,
        ));
    };
    check_builtin_arity(call, expected, actual)
}

pub(crate) fn check_builtin_direct_arity(
    call: BuiltinCall,
    builtin: Builtin,
    actual: usize,
) -> Result<(), TreeWalkError> {
    let Some(direct) = builtin.direct() else {
        return Err(TreeWalkError::new(
            TreeWalkErrorKind::UnsupportedPrimOp {
                id: call.id,
                symbol: call.symbol,
            },
            call.span,
        ));
    };
    check_builtin_arity(call, direct.arity(), actual)
}

pub(crate) fn check_builtin_arity(
    call: BuiltinCall,
    expected: usize,
    actual: usize,
) -> Result<(), TreeWalkError> {
    if actual == expected {
        return Ok(());
    }

    Err(TreeWalkError::new(
        TreeWalkErrorKind::InvalidPrimOpArity {
            id: call.id,
            symbol: call.symbol,
            expected,
            actual,
        },
        call.span,
    ))
}

pub(crate) fn lookup_builtin_by_symbol(symbols: &SymbolTable, symbol: Symbol) -> Option<Builtin> {
    symbols.resolve(symbol).and_then(lookup_builtin)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThrowAbortOp {
    Throw,
    Abort,
}

#[derive(Debug, Default)]
pub(crate) struct EqualityPairGuard {
    pub(crate) active: Vec<(Value, Value)>,
}

impl EqualityPairGuard {
    pub(crate) fn enter(&mut self, left: Value, right: Value) -> bool {
        if self.active.iter().any(|(active_left, active_right)| {
            (active_left.raw_eq(left) && active_right.raw_eq(right))
                || (active_left.raw_eq(right) && active_right.raw_eq(left))
        }) {
            return false;
        }
        self.active.push((left, right));
        true
    }

    pub(crate) fn exit(&mut self, left: Value, right: Value) {
        let active = self.active.pop();
        debug_assert!(active.is_some_and(|(active_left, active_right)| {
            active_left.raw_eq(left) && active_right.raw_eq(right)
        }));
    }
}

impl Number {
    pub(crate) fn to_float(self) -> f64 {
        match self {
            Self::Int(value) => value as f64,
            Self::Float(value) => value,
        }
    }
}

pub(crate) fn compare_numbers(op: ComparisonOp, left: Number, right: Number) -> bool {
    match (left, right) {
        (Number::Int(left), Number::Int(right)) => op.compare_ints(left, right),
        (left, right) => op.compare_floats(left.to_float(), right.to_float()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BinaryArithmeticOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BitwiseOp {
    And,
    Or,
    Xor,
}

impl BitwiseOp {
    pub(crate) const fn apply(self, left: i64, right: i64) -> i64 {
        match self {
            Self::And => left & right,
            Self::Or => left | right,
            Self::Xor => left ^ right,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllAnyOp {
    All,
    Any,
}

impl AllAnyOp {
    pub(crate) const fn short_circuits(self, value: bool) -> bool {
        match self {
            Self::All => !value,
            Self::Any => value,
        }
    }

    pub(crate) const fn short_circuit_value(self) -> bool {
        match self {
            Self::All => false,
            Self::Any => true,
        }
    }

    pub(crate) const fn empty_or_exhausted_value(self) -> bool {
        match self {
            Self::All => true,
            Self::Any => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ComparisonOp {
    Lt,
    Gt,
    Le,
    Ge,
}

impl ComparisonOp {
    pub(crate) const fn compare_ints(self, left: i64, right: i64) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }

    pub(crate) fn compare_floats(self, left: f64, right: f64) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }

    pub(crate) fn compare_bytes(self, left: &[u8], right: &[u8]) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }

    pub(crate) const fn compare_equal(self) -> bool {
        match self {
            Self::Lt | Self::Gt => false,
            Self::Le | Self::Ge => true,
        }
    }

    pub(crate) const fn compare_lengths(self, left: usize, right: usize) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }
}
