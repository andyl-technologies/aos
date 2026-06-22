//! Internal differential checks against the tree-walk oracle.
//!
//! Optimized execution tiers are allowed to be faster, not different. This
//! module provides the test/fuzz hook they use to compare their rendered result
//! against the safe tree-walk evaluator before the value reaches the external
//! `.drv` parity gate.

use thiserror::Error;

use crate::compile::Ir;

use super::tree_walk::{TreeWalkError, TreeWalkOptions, eval_raw_bytes_with_options};

/// An internal evaluator tier that can be checked against the tree-walk oracle.
pub trait InternalDiffTier {
    /// Returns the stable tier name used in diagnostics.
    fn name(&self) -> &'static str;

    /// Evaluates `ir` and renders a strict raw value for oracle comparison.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] when the tier cannot evaluate or render the
    /// requested value. Future non-tree-walk tiers should map their failures
    /// onto the tree-walk error taxonomy before returning here.
    fn eval_raw(&self, ir: &Ir, options: TreeWalkOptions) -> Result<Vec<u8>, TreeWalkError>;
}

/// Successful internal differential comparison output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalDiffReport {
    /// Candidate tier that matched the oracle.
    pub tier: &'static str,
    /// Canonical raw bytes produced by both the candidate and tree-walk oracle.
    pub raw: Vec<u8>,
}

/// Failure from an internal candidate-vs-oracle comparison.
#[derive(Debug, Error)]
pub enum InternalDiffError {
    /// The tree-walk oracle failed before a comparison was possible.
    #[error("tree-walk oracle failed before internal differential comparison: {source}")]
    Oracle {
        /// Oracle-side evaluation or rendering failure.
        #[source]
        source: TreeWalkError,
    },
    /// The candidate tier failed before a comparison was possible.
    #[error("{tier} failed before internal differential comparison: {source}")]
    Candidate {
        /// Candidate tier name.
        tier: &'static str,
        /// Candidate-side evaluation or rendering failure.
        #[source]
        source: TreeWalkError,
    },
    /// The candidate tier produced different bytes from the tree-walk oracle.
    #[error("{tier} diverged from the tree-walk oracle")]
    Divergence {
        /// Candidate tier name.
        tier: &'static str,
        /// Canonical raw bytes produced by the tree-walk oracle.
        oracle: Vec<u8>,
        /// Canonical raw bytes produced by the candidate tier.
        candidate: Vec<u8>,
    },
}

/// Compares an internal tier's strict raw rendering against the tree-walk oracle.
///
/// # Errors
///
/// Returns [`InternalDiffError::Oracle`] when the tree-walk oracle cannot
/// evaluate the expression, [`InternalDiffError::Candidate`] when the candidate
/// tier cannot evaluate it, or [`InternalDiffError::Divergence`] when both
/// evaluate successfully but produce different canonical raw bytes.
pub fn compare_raw_with_oracle<T>(
    tier: &T,
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<InternalDiffReport, InternalDiffError>
where
    T: InternalDiffTier + ?Sized,
{
    let tier_name = tier.name();
    let oracle = eval_raw_bytes_with_options(ir, options.clone())
        .map_err(|source| InternalDiffError::Oracle { source })?;
    let candidate = tier
        .eval_raw(ir, options)
        .map_err(|source| InternalDiffError::Candidate {
            tier: tier_name,
            source,
        })?;
    if oracle != candidate {
        return Err(InternalDiffError::Divergence {
            tier: tier_name,
            oracle,
            candidate,
        });
    }

    Ok(InternalDiffReport {
        tier: tier_name,
        raw: candidate,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::compile::{lower, resolve};
    use crate::syntax::parse_bytes;

    use super::*;

    struct MirrorTier;

    impl InternalDiffTier for MirrorTier {
        fn name(&self) -> &'static str {
            "mirror"
        }

        fn eval_raw(&self, ir: &Ir, options: TreeWalkOptions) -> Result<Vec<u8>, TreeWalkError> {
            eval_raw_bytes_with_options(ir, options)
        }
    }

    struct ConstantTier {
        raw: Vec<u8>,
    }

    impl InternalDiffTier for ConstantTier {
        fn name(&self) -> &'static str {
            "constant"
        }

        fn eval_raw(&self, _ir: &Ir, _options: TreeWalkOptions) -> Result<Vec<u8>, TreeWalkError> {
            Ok(self.raw.clone())
        }
    }

    fn ir(source: &str) -> Result<Ir> {
        let parsed = parse_bytes(source.as_bytes())?;
        let resolved = resolve(parsed)?;
        Ok(lower(resolved)?)
    }

    #[test]
    fn internal_diff_accepts_matching_tier() -> Result<()> {
        let ir = ir(r#"{ b = 2; a = [ 1 "x" ]; }"#)?;
        let report = compare_raw_with_oracle(&MirrorTier, &ir, TreeWalkOptions::default())?;

        assert_eq!(report.tier, "mirror");
        assert_eq!(report.raw, br#"{ a = [ 1 "x" ]; b = 2; }"#);
        Ok(())
    }

    #[test]
    fn internal_diff_rejects_divergent_tier() -> Result<()> {
        let ir = ir("1 + 1")?;
        let error = compare_raw_with_oracle(
            &ConstantTier { raw: b"3".to_vec() },
            &ir,
            TreeWalkOptions::default(),
        )
        .expect_err("constant tier should diverge from oracle");

        match error {
            InternalDiffError::Divergence {
                tier,
                oracle,
                candidate,
            } => {
                assert_eq!(tier, "constant");
                assert_eq!(oracle, b"2");
                assert_eq!(candidate, b"3");
            }
            other => panic!("unexpected internal diff error: {other:#}"),
        }
        Ok(())
    }
}
