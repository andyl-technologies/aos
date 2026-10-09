//! Exhaustive finite assignments using precomputed charge matrices.
//!
//! Choices are integers: zero means deferred and one through the destination
//! count select destinations. Charge matrices and accepted cardinalities are
//! supplied by fixtures rather than derived from the production model. The
//! oracle never calls model validation, evaluation, verification, or search.

use std::collections::BTreeSet;

/// A small exact fraction used only within explicitly bounded fixture domains.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Fraction {
    /// Signed numerator.
    pub numerator: i128,
    /// Strictly positive denominator.
    pub denominator: i128,
}

impl Fraction {
    /// Constructs a fraction without rounding.
    ///
    /// # Panics
    ///
    /// Panics when the denominator is not positive.
    pub fn new(numerator: i128, denominator: i128) -> Self {
        assert!(denominator > 0);
        Self {
            numerator,
            denominator,
        }
    }

    /// Adds two fixture fractions using checked arithmetic.
    ///
    /// # Panics
    ///
    /// Panics when a fixture exceeds the oracle's bounded arithmetic domain.
    pub fn plus(self, other: Self) -> Self {
        let numerator = self
            .numerator
            .checked_mul(other.denominator)
            .and_then(|left| {
                other
                    .numerator
                    .checked_mul(self.denominator)
                    .and_then(|right| left.checked_add(right))
            })
            .expect("fixture fraction addition stays within i128");
        let denominator = self
            .denominator
            .checked_mul(other.denominator)
            .expect("fixture denominator stays within i128");
        Self::new(numerator, denominator)
    }

    /// Multiplies a fraction by an exact fixture coefficient.
    ///
    /// # Panics
    ///
    /// Panics when a fixture exceeds the oracle's bounded arithmetic domain.
    pub fn times(self, other: Self) -> Self {
        Self::new(
            self.numerator
                .checked_mul(other.numerator)
                .expect("fixture numerator stays within i128"),
            self.denominator
                .checked_mul(other.denominator)
                .expect("fixture denominator stays within i128"),
        )
    }

    /// Returns the absolute value of a fixture fraction.
    ///
    /// # Panics
    ///
    /// Panics if the numerator is the minimum signed integer.
    pub fn absolute(self) -> Self {
        Self::new(
            self.numerator
                .checked_abs()
                .expect("fixture numerator has an absolute value"),
            self.denominator,
        )
    }
}

impl PartialEq for Fraction {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl PartialOrd for Fraction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Fraction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let left = self
            .numerator
            .checked_mul(other.denominator)
            .expect("fixture comparison stays within i128");
        let right = other
            .numerator
            .checked_mul(self.denominator)
            .expect("fixture comparison stays within i128");
        left.cmp(&right)
    }
}

/// A finite linear charge table with fixture-defined observed debt allowance.
#[derive(Clone, Debug)]
pub struct Bound {
    /// Contribution for each item and choice.
    pub coefficients: Vec<Vec<u128>>,
    /// Occupancy unaffected by the assignment.
    pub constant: u128,
    /// Inclusive lower bound, when specified.
    pub minimum: Option<u128>,
    /// Inclusive upper bound, when specified.
    pub maximum: Option<u128>,
    /// Permitted lower-bound debt, zero for hard enforcement.
    pub lower_allowance: u128,
    /// Permitted upper-bound debt, zero for hard enforcement.
    pub upper_allowance: u128,
}

impl Bound {
    fn value(&self, choices: &[usize]) -> u128 {
        choices
            .iter()
            .enumerate()
            .fold(self.constant, |total, (item, choice)| {
                total
                    .checked_add(self.coefficients[item][*choice])
                    .expect("fixture aggregate stays within u128")
            })
    }

    fn debt(&self, choices: &[usize]) -> (u128, u128) {
        let value = self.value(choices);
        (
            self.minimum
                .map_or(0, |minimum| minimum.saturating_sub(value)),
            self.maximum
                .map_or(0, |maximum| value.saturating_sub(maximum)),
        )
    }
}

/// A finite relation whose accepted tuples are independent fixture data.
#[derive(Clone, Debug)]
pub struct Relation {
    /// Ordered item coordinates to project out of a complete assignment.
    pub items: Vec<usize>,
    /// Exactly the allowed projected tuples.
    pub allowed: BTreeSet<Vec<usize>>,
}

/// A linear rational objective with explicit choice coefficients.
#[derive(Clone, Debug)]
pub struct Objective {
    /// Contribution for every item and choice, already oriented to minimization.
    pub coefficients: Vec<Vec<Fraction>>,
    /// Assignment-independent objective contribution.
    pub constant: Fraction,
}

/// A small independent problem described by linear charges and accepted tuples.
#[derive(Clone, Debug)]
pub struct Problem {
    /// Number of destinations; choice zero remains the deferred alternative.
    pub targets: usize,
    /// Allowed choices for each item.
    pub domains: Vec<BTreeSet<usize>>,
    /// Independent capacity, admission, movement, or per-domain bounds.
    pub bounds: Vec<Bound>,
    /// Exact tuple relations for atomic admission, placement, or distinctness.
    pub relations: Vec<Relation>,
    /// Ordered objective tiers.
    pub objectives: Vec<Objective>,
}

/// The exhaustive oracle's classification and exact objective vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answer {
    /// Whether the assignment respects every bound and tuple relation.
    pub accepted: bool,
    /// Whether an accepted assignment retains numeric debt.
    pub repair: bool,
    /// Lower and upper debt for each declared independent bound.
    pub debts: Vec<(u128, u128)>,
    /// Ordered rational objective values.
    pub objectives: Vec<Fraction>,
}

impl Problem {
    /// Enumerates all complete tuples, including forbidden choices.
    ///
    /// Forbidden tuples remain useful because evaluators must reject them.
    pub fn assignments(&self) -> Vec<Vec<usize>> {
        let mut tuples = vec![Vec::new()];
        for _ in &self.domains {
            tuples = tuples
                .into_iter()
                .flat_map(|prefix| {
                    (0..=self.targets).map(move |choice| {
                        let mut tuple = prefix.clone();
                        tuple.push(choice);
                        tuple
                    })
                })
                .collect();
        }
        tuples
    }

    /// Classifies a complete fixture tuple without consulting Dispatch.
    ///
    /// # Panics
    ///
    /// Panics for a malformed fixture tuple or overflowing fixture arithmetic.
    pub fn classify(&self, choices: &[usize]) -> Answer {
        assert_eq!(choices.len(), self.domains.len());
        let debts: Vec<_> = self
            .bounds
            .iter()
            .map(|bound| bound.debt(choices))
            .collect();
        let domains_hold = choices
            .iter()
            .zip(&self.domains)
            .all(|(choice, domain)| domain.contains(choice));
        let bounds_hold = self
            .bounds
            .iter()
            .zip(&debts)
            .all(|(bound, (lower, upper))| {
                *lower <= bound.lower_allowance && *upper <= bound.upper_allowance
            });
        let relations_hold = self.relations.iter().all(|relation| {
            let projection: Vec<_> = relation.items.iter().map(|item| choices[*item]).collect();
            relation.allowed.contains(&projection)
        });
        let objectives = self
            .objectives
            .iter()
            .map(|objective| {
                choices
                    .iter()
                    .enumerate()
                    .fold(objective.constant, |total, (item, choice)| {
                        total.plus(objective.coefficients[item][*choice])
                    })
            })
            .collect();

        let accepted = domains_hold && bounds_hold && relations_hold;
        Answer {
            accepted,
            repair: accepted && debts.iter().any(|debt| *debt != (0, 0)),
            debts,
            objectives,
        }
    }
}
