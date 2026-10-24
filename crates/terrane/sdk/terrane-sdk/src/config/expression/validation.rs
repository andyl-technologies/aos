//! Checks the shape and capability compatibility of already opened stores.
//!
//! The trusted loader opens and probes each backend, constructs its actual
//! combinators, and supplies their reports in the same shape as the parsed
//! expression. Named policy compilation supplies each position's requirements.
//! Validation cannot replace those probes or manufacture a store, authorization,
//! native custody, presigned URL or publication acknowledgement.
//!
//! ```text
//! parsed expression + opened backend tree + compiled position requirements
//!   -> compatible configuration, or a load-time refusal
//! ```

use std::fmt;

use super::StoreExpression;
use crate::store::{CapabilityReport, RefCapability};

/// Describes policy requirements at one already opened expression position.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PositionRequirements {
    /// Requires CAS when this position is a guard accepting concurrent writers.
    pub multiple_writers: bool,
    /// Requires actual presigning support at this position.
    pub presign: bool,
}

/// Borrows actual opened reports in the parsed expression's child order.
///
/// The trusted loader must supply the real backend at every position, including
/// the actual combinator's report. Configuration assertions and cached remote
/// advertisements cannot substitute for a backend's successful opening probes.
/// This tree is validation input; constructing it grants no authority.
pub struct OpenedStore<'store> {
    /// Borrows the actual store implementing this expression position.
    pub backend: &'store dyn CapabilityReport,
    /// Contains the already opened children in configuration order.
    pub children: Vec<Self>,
    /// Supplies requirements compiled from the trusted policy for this position.
    pub requirements: PositionRequirements,
}

impl<'store> OpenedStore<'store> {
    /// Borrows an opened leaf without adding policy requirements.
    pub fn leaf(backend: &'store dyn CapabilityReport) -> Self {
        Self {
            backend,
            children: Vec::new(),
            requirements: PositionRequirements::default(),
        }
    }
}

/// Reports an incompatible opened expression without granting partial acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// Opened children do not have the parsed expression's shape.
    Shape,
    /// More than one authority is reachable through a routed spine.
    MultipleAuthorities,
    /// A shared directory incorrectly advertises mutable ref authority.
    SharedDirectoryAuthority,
    /// A combinator advertises a ref mode incompatible with its children.
    RefCapability,
    /// A concurrent-writer guard would use a single-writer authority.
    SingleWriter,
    /// Required presigning is unavailable at the configured position.
    Presign,
    /// Concurrent-writer policy is attached to a position other than a guard.
    WriterPolicy,
    /// An optional storage combinator has no supported trunk implementation.
    UnsupportedCombinator,
}

impl StoreExpression {
    /// Validates the complete opened tree before the loader exposes any store.
    ///
    /// A routed spine has at most one authority. Guard wrappers preserve their
    /// child's ref mode; cache wrappers expose none. Shared directories cannot
    /// supply refs. Every position must satisfy its compiled policy requirements.
    /// Replicated and striped expressions remain unavailable in the trunk.
    ///
    /// This checks startup capability reports only. Operations still need fresh
    /// authorization, backend validation and their own actual durability proofs.
    ///
    /// # Errors
    /// Rejects shape mismatches, conflicting or incompatible ref authority,
    /// a single-writer authority under a concurrent-writer guard, unavailable
    /// required presigning, misplaced policy or unsupported combinators.
    pub fn validate_opened(&self, opened: &OpenedStore<'_>) -> Result<(), ValidationError> {
        self.checked_ref_mode(opened).map(|_| ())
    }

    fn checked_ref_mode(&self, opened: &OpenedStore<'_>) -> Result<RefCapability, ValidationError> {
        if self.children().len() != opened.children.len() {
            return Err(ValidationError::Shape);
        }
        let actual = opened.backend.capabilities();
        if opened.requirements.presign && !actual.presign {
            return Err(ValidationError::Presign);
        }
        if opened.requirements.multiple_writers && self.name() != "guard" {
            return Err(ValidationError::WriterPolicy);
        }

        // Inspect every child before dropping a cache's ref interface. An
        // invalid inner route cannot become constructible by wrapping it.
        let children = self
            .children()
            .iter()
            .zip(&opened.children)
            .map(|(expression, child)| expression.checked_ref_mode(child))
            .collect::<Result<Vec<_>, _>>()?;

        let expected = match self.name() {
            "shared-dir" if actual.refs != RefCapability::None => {
                return Err(ValidationError::SharedDirectoryAuthority);
            }
            "bucket" | "disk" | "shared-dir" | "blockdev" | "remote" => actual.refs,
            "cache" => RefCapability::None,
            "guard" => {
                let [child] = children.as_slice() else {
                    return Err(ValidationError::Shape);
                };
                if opened.requirements.multiple_writers && *child == RefCapability::SingleWriter {
                    return Err(ValidationError::SingleWriter);
                }
                *child
            }
            "routed" => {
                let mut authorities = children
                    .into_iter()
                    .filter(|mode| *mode != RefCapability::None);
                let mode = authorities.next().unwrap_or(RefCapability::None);
                if authorities.next().is_some() {
                    return Err(ValidationError::MultipleAuthorities);
                }
                mode
            }
            "replicated" | "striped" => return Err(ValidationError::UnsupportedCombinator),
            _ => return Err(ValidationError::Shape),
        };
        if actual.refs != expected {
            return Err(ValidationError::RefCapability);
        }

        Ok(actual.refs)
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Shape => "opened store tree differs from its expression",
            Self::MultipleAuthorities => "routed store has multiple ref authorities",
            Self::SharedDirectoryAuthority => "shared-dir cannot be a ref authority",
            Self::RefCapability => "combinator ref capability differs from its children",
            Self::SingleWriter => "concurrent-writer guard requires a CAS authority",
            Self::Presign => "configured store position requires presigned reads",
            Self::WriterPolicy => "concurrent-writer policy requires a guard position",
            Self::UnsupportedCombinator => "storage combinator is unavailable in the trunk",
        })
    }
}

impl std::error::Error for ValidationError {}
