//! Complete NVD configuration expressions evaluated using three-valued logic.
//!
//! A positive environmental term alone never establishes a vulnerable product.
//! Unsupported CPE syntax/qualifiers and missing environment evidence remain
//! unknown; configurations are never flattened into a union of product names.
//!
//! ```json
//! {"kind":"expression","operator":"and","negate":false,"children":[]}
//! ```

use std::cmp::Ordering;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::ranges::{Truth, compare_versions};
use crate::scan_inventory::ComponentInstance;
use crate::security::SecurityIdentity;
use crate::validation::text;

/// Selects the source configuration's logical operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operator {
    /// Requires every supported child condition.
    And,
    /// Requires at least one supported child condition.
    Or,
}

/// Preserves one complete normalized NVD configuration tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Configuration {
    /// Combines complete child expressions without discarding environment terms.
    Expression {
        /// Exact source logical operator.
        operator: Operator,
        /// Exact source negation flag.
        negate: bool,
        /// Source-ordered children.
        children: Vec<Configuration>,
    },
    /// Binds a CPE claim, vulnerable association and complete version bounds.
    Match {
        /// Original CPE 2.3 criteria; unsupported syntax is retained.
        criteria: String,
        /// Marks a vulnerable product rather than only an environment condition.
        vulnerable: bool,
        /// Optional inclusive lower version bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version_start_including: Option<String>,
        /// Optional exclusive lower version bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version_start_excluding: Option<String>,
        /// Optional inclusive upper version bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version_end_including: Option<String>,
        /// Optional exclusive upper version bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version_end_excluding: Option<String>,
    },
    /// Retains a decision-relevant source construct with no admitted semantics.
    Unsupported {
        /// Stable limitation identity.
        reason: String,
    },
}

/// Separates environmental applicability from a relevant vulnerable association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationResult {
    /// Applicability of the complete environment expression.
    pub environment: Truth,
    /// Applicability with a vulnerable association to the assessed component.
    pub affected: Truth,
}

impl Configuration {
    /// Validates bounded expressions before recursion or evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error for excessive nesting/node counts, empty expressions,
    /// invalid text or mutually exclusive duplicate bound types.
    pub fn validate(&self) -> Result<()> {
        let mut pending = vec![(self, 1)];
        let mut count = 0;
        while let Some((node, depth)) = pending.pop() {
            count += 1;
            if count > 4096 || depth > 12 {
                bail!("NVD configuration exceeds bounded expression scope");
            }
            match node {
                Self::Expression { children, .. } => {
                    if children.is_empty() || children.len() > 128 {
                        bail!("NVD expression requires bounded nonempty children");
                    }
                    pending.extend(children.iter().map(|child| (child, depth + 1)));
                }
                Self::Match {
                    criteria,
                    version_start_including,
                    version_start_excluding,
                    version_end_including,
                    version_end_excluding,
                    ..
                } => {
                    text(criteria, 2048, "NVD CPE criteria")?;
                    if (version_start_including.is_some() && version_start_excluding.is_some())
                        || (version_end_including.is_some() && version_end_excluding.is_some())
                    {
                        bail!("NVD configuration has conflicting version bounds");
                    }
                    for bound in [
                        version_start_including,
                        version_start_excluding,
                        version_end_including,
                        version_end_excluding,
                    ]
                    .into_iter()
                    .flatten()
                    {
                        text(bound, 256, "NVD version bound")?;
                    }
                }
                Self::Unsupported { reason } => text(reason, 128, "unsupported NVD expression")?,
            }
        }
        Ok(())
    }

    /// Evaluates a complete expression against explicit inventory facts.
    ///
    /// # Errors
    ///
    /// Returns an error for structurally invalid/excessive expressions. Missing
    /// environment facts and unsupported CPE/comparator constructs stay unknown.
    pub fn evaluate(
        &self,
        target: &ComponentInstance,
        environment: &[ComponentInstance],
    ) -> Result<ConfigurationResult> {
        self.validate()?;
        Ok(self.evaluate_inner(target, environment))
    }

    fn evaluate_inner(
        &self,
        target: &ComponentInstance,
        environment: &[ComponentInstance],
    ) -> ConfigurationResult {
        match self {
            Self::Unsupported { .. } => unknown(),
            Self::Match { vulnerable, .. } => {
                let target_match = self.match_component(target);
                let environment_match = if *vulnerable {
                    target_match
                } else {
                    environment.iter().fold(Truth::Unknown, |found, component| {
                        found.or(self.match_component(component))
                    })
                };
                ConfigurationResult {
                    environment: environment_match,
                    affected: if *vulnerable {
                        target_match
                    } else {
                        Truth::False
                    },
                }
            }
            Self::Expression {
                operator,
                negate,
                children,
            } => {
                let mut environment_result = match operator {
                    Operator::And => Truth::True,
                    Operator::Or => Truth::False,
                };
                let mut vulnerable_result = Truth::False;
                for child in children {
                    let result = child.evaluate_inner(target, environment);
                    environment_result = match operator {
                        Operator::And => environment_result.and(result.environment),
                        Operator::Or => environment_result.or(result.environment),
                    };
                    vulnerable_result = vulnerable_result.or(result.affected);
                }
                if *negate {
                    return ConfigurationResult {
                        environment: environment_result.negate(),
                        affected: if vulnerable_result == Truth::False {
                            Truth::False
                        } else {
                            Truth::Unknown
                        },
                    };
                }
                ConfigurationResult {
                    environment: environment_result,
                    affected: environment_result.and(vulnerable_result),
                }
            }
        }
    }

    fn match_component(&self, component: &ComponentInstance) -> Truth {
        let Self::Match {
            criteria,
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
            ..
        } = self
        else {
            return Truth::Unknown;
        };
        let parts = criteria.split(':').collect::<Vec<_>>();
        if parts.len() != 13 || parts[0] != "cpe" || parts[1] != "2.3" || criteria.contains('\\') {
            return Truth::Unknown;
        }
        if parts[3].contains(['*', '?']) || parts[4].contains(['*', '?']) {
            return Truth::Unknown;
        }
        let mut product = Truth::False;
        for identity in &component.security.identities {
            let SecurityIdentity::Cpe {
                part,
                vendor,
                product: name,
                edition,
                target_software,
                target_hardware,
            } = identity
            else {
                continue;
            };
            if parts[2] != part || parts[3] != vendor || parts[4] != name {
                continue;
            }
            let mut matches = Truth::True;
            for (constraint, fact) in [
                (parts[7], edition.as_deref()),
                (parts[10], target_software.as_deref()),
                (parts[11], target_hardware.as_deref()),
            ] {
                if constraint != "*" {
                    matches = matches.and(match fact {
                        Some(value) if value == constraint => Truth::True,
                        Some(_) => Truth::False,
                        None => Truth::Unknown,
                    });
                }
            }
            if [parts[6], parts[8], parts[9], parts[12]]
                .iter()
                .any(|value| *value != "*")
            {
                matches = matches.and(Truth::Unknown);
            }
            if parts[5] != "*" {
                matches = matches.and(comparison(component, parts[5], |order| {
                    order == Ordering::Equal
                }));
            }
            for (bound, allowed) in [
                (
                    version_start_including,
                    (Ordering::Equal, Ordering::Greater),
                ),
                (
                    version_start_excluding,
                    (Ordering::Greater, Ordering::Greater),
                ),
                (version_end_including, (Ordering::Less, Ordering::Equal)),
                (version_end_excluding, (Ordering::Less, Ordering::Less)),
            ] {
                if let Some(bound) = bound {
                    matches = matches.and(comparison(component, bound, |order| {
                        order == allowed.0 || order == allowed.1
                    }));
                }
            }
            product = product.or(matches);
        }
        product
    }
}

fn comparison(
    component: &ComponentInstance,
    bound: &str,
    predicate: impl FnOnce(Ordering) -> bool,
) -> Truth {
    match compare_versions(
        component.security.version_scheme,
        &component.current.comparison_version,
        bound,
    ) {
        Ok(Some(ordering)) if predicate(ordering) => Truth::True,
        Ok(Some(_)) => Truth::False,
        Ok(None) | Err(_) => Truth::Unknown,
    }
}

fn unknown() -> ConfigurationResult {
    ConfigurationResult {
        environment: Truth::Unknown,
        affected: Truth::Unknown,
    }
}
