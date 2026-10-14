//! Immutable choice-domain ownership and constructor-derived data identities.
//!
//! This wrapper owns the exact domain moved through an opportunity constructor.
//! Its identities describe those immutable bytes; they confer no producer,
//! backend, capability, or execution permission. Raw domain and selection APIs
//! continue to validate their inputs independently.

use std::fmt;

use super::{ChoiceDomain, ChoiceOpportunity};
use crate::{ChoiceDomainId, ChoiceDomainSemanticId};

/// Owns one immutable domain and its original constructor-derived identities.
///
/// [`ChoiceOpportunity::new_with_owned_domain`] constructs this data wrapper
/// only after the ordinary opportunity constructor completes. Read-only domain
/// access preserves its bytes and identity; no mutable access or deserialization
/// can substitute another domain under the retained identities.
///
/// Read-only access cannot replace the retained domain:
///
/// ```compile_fail
/// use crucible_campaign::{ChoiceDomain, ImmutableChoiceDomain};
///
/// fn replace(owner: &mut ImmutableChoiceDomain, other: ChoiceDomain) {
///     *owner.as_domain() = other;
/// }
/// ```
#[derive(Clone)]
pub struct ImmutableChoiceDomain {
    domain: ChoiceDomain,
    identity: ChoiceDomainId,
    semantic_identity: ChoiceDomainSemanticId,
}

impl ImmutableChoiceDomain {
    pub(super) fn from_constructor(domain: ChoiceDomain, opportunity: &ChoiceOpportunity) -> Self {
        Self {
            domain,
            identity: opportunity.domain(),
            semantic_identity: opportunity.domain_semantics(),
        }
    }

    /// Returns the original immutable domain.
    #[must_use]
    pub const fn as_domain(&self) -> &ChoiceDomain {
        &self.domain
    }

    /// Returns the canonical identity computed by the original constructor.
    #[must_use]
    pub const fn id(&self) -> ChoiceDomainId {
        self.identity
    }

    /// Returns the semantic identity computed by the original constructor.
    #[must_use]
    pub const fn semantic_id(&self) -> ChoiceDomainSemanticId {
        self.semantic_identity
    }
}

// Cache fields are derived data, not new observable domain contents. Preserve
// the existing domain's Debug and equality semantics when used by an owner.
impl fmt::Debug for ImmutableChoiceDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.domain, formatter)
    }
}

impl PartialEq for ImmutableChoiceDomain {
    fn eq(&self, other: &Self) -> bool {
        self.domain == other.domain
    }
}

impl Eq for ImmutableChoiceDomain {}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "exact constructor and error-order fixtures fail at their original assertion"
)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        AlternativeId, BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceCoordinate,
        ChoiceGroup, ChoiceGroupApplication, ChoiceGroupDomain, ChoiceSource, ChoiceTuple,
        ChoiceValue, ConfigurationId, DiscreteAlternative, DiscreteDomain, ExactRational,
        IntegerDomain, IntegerRepresentation, IntegerValue, ScenarioDefId, SelectableDeclaration,
        Selection,
    };

    fn declaration(version: u32) -> (ChoiceDomain, SelectableDeclaration) {
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(version).expect("boolean domain"));
        let declaration = SelectableDeclaration::new(
            "owned-domain",
            ChoiceSource::Scheduler {
                producer: String::from("owned-domain"),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::from([String::from("owned")])).expect("class"),
            BTreeSet::new(),
            false,
        )
        .expect("declaration");
        (domain, declaration)
    }

    fn opportunity(version: u32) -> (ChoiceOpportunity, ImmutableChoiceDomain) {
        let (domain, declaration) = declaration(version);
        ChoiceOpportunity::new_with_owned_domain(
            ScenarioDefId::from_hash(CampaignHash::from_bytes([1; 32])),
            &declaration,
            domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::from_bytes([2; 32]),
                producer: CampaignHash::from_bytes([3; 32]),
            },
            "original",
            None,
        )
        .expect("owned opportunity")
    }

    #[test]
    fn owned_domain_retains_constructor_ids_bytes_debug_and_equality() {
        let (opportunity, owner) = opportunity(1);
        let original = owner.as_domain();

        assert_eq!(owner.id(), original.id().expect("original domain id"));
        assert_eq!(owner.semantic_id(), original.semantic_id());
        assert_eq!(owner.id(), opportunity.domain());
        assert_eq!(owner.semantic_id(), opportunity.domain_semantics());
        assert_eq!(format!("{owner:?}"), format!("{original:?}"));
        assert_eq!(owner.clone(), owner);
        assert_eq!(
            owner.clone().as_domain().canonical_bytes(),
            original.canonical_bytes()
        );
    }

    #[test]
    fn owned_domain_constructor_preserves_original_error_order() {
        let (domain, original_declaration) = declaration(1);
        let (other_domain, _) = declaration(2);
        let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes([1; 32]));
        let coordinate = ChoiceCoordinate {
            scheduler: CampaignHash::from_bytes([2; 32]),
            producer: CampaignHash::from_bytes([3; 32]),
        };

        for (offered, instance) in [(domain, ""), (other_domain, "invalid/instance")] {
            let ordinary = ChoiceOpportunity::new(
                scenario,
                &original_declaration,
                &offered,
                coordinate,
                instance,
                None,
            );
            let owned = ChoiceOpportunity::new_with_owned_domain(
                scenario,
                &original_declaration,
                offered,
                coordinate,
                instance,
                None,
            );
            assert!(ordinary.is_err());
            assert_eq!(owned.map(|(opportunity, _)| opportunity), ordinary);
        }
    }

    #[test]
    fn owned_domain_branch_replay_matches_raw_and_refuses_changed_context() {
        let (original, owner) = opportunity(1);
        let (foreign, foreign_owner) = opportunity(2);
        let parent = ConfigurationId::from_hash(CampaignHash::from_bytes([4; 32]));
        let point = original.branch_point_id(parent);
        let wrong_point = original.branch_point_id(ConfigurationId::from_hash(
            CampaignHash::from_bytes([5; 32]),
        ));

        for value in [ChoiceValue::Boolean(false), ChoiceValue::Boolean(true)] {
            let ordinary =
                Selection::new_campaign_branch(&original, owner.as_domain(), value.clone(), point)
                    .expect("raw branch");
            let owned =
                Selection::new_campaign_branch_owned_domain(&original, &owner, value, point)
                    .expect("owned branch");
            assert_eq!(owned.canonical_bytes(), ordinary.canonical_bytes());
            assert_eq!(owned.id(), ordinary.id());
            for (context, domain, tested_point) in [
                (&original, &owner, point),
                (&original, &owner, wrong_point),
                (&foreign, &owner, wrong_point),
                (&original, &foreign_owner, wrong_point),
            ] {
                assert_eq!(
                    owned.validate_branch_replay_owned_domain(context, domain, tested_point),
                    ordinary.validate_branch_replay(context, domain.as_domain(), tested_point)
                );
            }
            assert_eq!(
                Selection::new_campaign_branch_owned_domain(
                    &foreign,
                    &owner,
                    owned.value().clone(),
                    point
                ),
                Selection::new_campaign_branch(
                    &foreign,
                    owner.as_domain(),
                    owned.value().clone(),
                    point
                )
            );
        }
    }

    fn general_declaration(
        name: &str,
        domain: ChoiceDomain,
        default: ChoiceValue,
    ) -> SelectableDeclaration {
        SelectableDeclaration::new(
            name,
            ChoiceSource::Scheduler {
                producer: String::from("owned-domain"),
            },
            domain,
            default,
            ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
            BTreeSet::new(),
            false,
        )
        .expect("generic declaration")
    }

    fn discrete_fixture() -> (
        ChoiceDomain,
        ChoiceValue,
        Vec<ChoiceValue>,
        Vec<ChoiceValue>,
    ) {
        let first = AlternativeId::from_hash(CampaignHash::from_bytes([10; 32]));
        let second = AlternativeId::from_hash(CampaignHash::from_bytes([11; 32]));
        let domain = ChoiceDomain::Discrete(
            DiscreteDomain::new(
                1,
                BTreeMap::from([
                    (
                        first,
                        DiscreteAlternative::new(first, "first", None).expect("first alternative"),
                    ),
                    (
                        second,
                        DiscreteAlternative::new(second, "second", None)
                            .expect("second alternative"),
                    ),
                ]),
            )
            .expect("discrete domain"),
        );
        (
            domain,
            ChoiceValue::Discrete(first),
            vec![ChoiceValue::Discrete(first), ChoiceValue::Discrete(second)],
            vec![
                ChoiceValue::Discrete(AlternativeId::from_hash(CampaignHash::from_bytes([12; 32]))),
                ChoiceValue::Boolean(true),
            ],
        )
    }

    fn integer_fixture() -> (
        ChoiceDomain,
        ChoiceValue,
        Vec<ChoiceValue>,
        Vec<ChoiceValue>,
    ) {
        let domain = ChoiceDomain::Integer(
            IntegerDomain::new(
                1,
                IntegerRepresentation::Unsigned64,
                IntegerValue::Unsigned(0),
                IntegerValue::Unsigned(4),
                2,
                None,
                ExactRational::new(1, 1).expect("exact scale"),
                Vec::new(),
            )
            .expect("integer domain"),
        );
        (
            domain,
            ChoiceValue::Integer(IntegerValue::Unsigned(0)),
            vec![
                ChoiceValue::Integer(IntegerValue::Unsigned(0)),
                ChoiceValue::Integer(IntegerValue::Unsigned(2)),
                ChoiceValue::Integer(IntegerValue::Unsigned(4)),
            ],
            vec![
                ChoiceValue::Integer(IntegerValue::Unsigned(3)),
                ChoiceValue::Integer(IntegerValue::Unsigned(6)),
                ChoiceValue::Boolean(true),
            ],
        )
    }

    fn group_fixture() -> (
        ChoiceDomain,
        ChoiceValue,
        Vec<ChoiceValue>,
        Vec<ChoiceValue>,
    ) {
        let member = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("member domain"));
        let first_declaration =
            general_declaration("first-member", member.clone(), ChoiceValue::Boolean(false));
        let second_declaration =
            general_declaration("second-member", member.clone(), ChoiceValue::Boolean(true));
        let first = first_declaration.id().expect("first member id");
        let second = second_declaration.id().expect("second member id");
        let declarations =
            BTreeMap::from([(first, first_declaration), (second, second_declaration)]);
        let tuple = ChoiceTuple::new(BTreeMap::from([
            (first, ChoiceValue::Boolean(false)),
            (second, ChoiceValue::Boolean(true)),
        ]));
        let policy = ChoiceGroupDomain::Finite {
            members: BTreeMap::from([(first, member.clone()), (second, member)]),
            tuples: BTreeSet::from([tuple.clone()]),
        };
        let group = ChoiceGroup::new(
            &declarations,
            policy.clone(),
            ChoiceGroupApplication::new("owned.group", 1).expect("group application"),
        )
        .expect("actual group");
        let foreign = ChoiceGroup::new(
            &declarations,
            policy,
            ChoiceGroupApplication::new("foreign.group", 1).expect("foreign application"),
        )
        .expect("foreign group");

        assert!(
            group
                .select(ChoiceTuple::new(BTreeMap::from([(
                    first,
                    ChoiceValue::Boolean(false)
                )])))
                .is_err()
        );
        assert!(
            group
                .select(ChoiceTuple::new(BTreeMap::from([
                    (first, ChoiceValue::Boolean(true)),
                    (second, ChoiceValue::Boolean(true))
                ])))
                .is_err()
        );
        let valid =
            ChoiceValue::Group(group.select(tuple.clone()).expect("allowed complete tuple"));
        let wrong_reference =
            ChoiceValue::Group(foreign.select(tuple).expect("actual foreign tuple"));
        assert!(!ChoiceDomain::Group(Box::new(group.clone())).contains(&wrong_reference));
        (
            ChoiceDomain::Group(Box::new(group)),
            valid.clone(),
            vec![valid],
            vec![wrong_reference, ChoiceValue::Boolean(true)],
        )
    }

    #[test]
    fn owned_domain_parity_covers_discrete_integer_and_actual_group() {
        let parent = ConfigurationId::from_hash(CampaignHash::from_bytes([4; 32]));
        let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes([1; 32]));
        let coordinate = ChoiceCoordinate {
            scheduler: CampaignHash::from_bytes([2; 32]),
            producer: CampaignHash::from_bytes([3; 32]),
        };
        let (foreign_opportunity, foreign_owner) = opportunity(2);

        for (offered, default, accepted, rejected) in
            [discrete_fixture(), integer_fixture(), group_fixture()]
        {
            let declaration = general_declaration("generic-owned", offered.clone(), default);
            let raw = ChoiceOpportunity::new(
                scenario,
                &declaration,
                &offered,
                coordinate,
                "original",
                None,
            )
            .expect("ordinary generic opportunity");
            let (original, owner) = ChoiceOpportunity::new_with_owned_domain(
                scenario,
                &declaration,
                offered,
                coordinate,
                "original",
                None,
            )
            .expect("owned generic opportunity");
            let point = original.branch_point_id(parent);
            let wrong_point = original.branch_point_id(ConfigurationId::from_hash(
                CampaignHash::from_bytes([5; 32]),
            ));

            assert_eq!(original.canonical_bytes(), raw.canonical_bytes());
            assert_eq!(
                owner.id(),
                owner.as_domain().id().expect("original generic domain id")
            );
            assert_eq!(owner.semantic_id(), owner.as_domain().semantic_id());
            assert_eq!(format!("{owner:?}"), format!("{:?}", owner.as_domain()));
            for value in accepted {
                let ordinary = Selection::new_campaign_branch(
                    &original,
                    owner.as_domain(),
                    value.clone(),
                    point,
                )
                .expect("ordinary generic branch");
                let owned =
                    Selection::new_campaign_branch_owned_domain(&original, &owner, value, point)
                        .expect("owned generic branch");
                assert_eq!(owned.canonical_bytes(), ordinary.canonical_bytes());
                for (context, domain, replay_point) in [
                    (&original, &owner, point),
                    (&original, &owner, wrong_point),
                    (&foreign_opportunity, &owner, wrong_point),
                    (&original, &foreign_owner, wrong_point),
                ] {
                    assert_eq!(
                        owned.validate_branch_replay_owned_domain(context, domain, replay_point),
                        ordinary.validate_branch_replay(context, domain.as_domain(), replay_point)
                    );
                }
            }
            for value in rejected {
                let ordinary = Selection::new_campaign_branch(
                    &original,
                    owner.as_domain(),
                    value.clone(),
                    point,
                );
                assert!(ordinary.is_err());
                assert_eq!(
                    Selection::new_campaign_branch_owned_domain(&original, &owner, value, point),
                    ordinary
                );
            }
        }
    }

    #[test]
    fn owned_domain_moves_original_storage_and_reports_fixed_geometry() {
        let (offered, default, _, _) = discrete_fixture();
        let ChoiceDomain::Discrete(before) = &offered else {
            panic!("discrete fixture");
        };
        let label_before = before
            .alternatives()
            .first_key_value()
            .expect("original alternative")
            .1
            .label()
            .as_ptr();
        let declaration = general_declaration("moved-storage", offered.clone(), default);
        let (_, owner) = ChoiceOpportunity::new_with_owned_domain(
            ScenarioDefId::from_hash(CampaignHash::from_bytes([1; 32])),
            &declaration,
            offered,
            ChoiceCoordinate {
                scheduler: CampaignHash::from_bytes([2; 32]),
                producer: CampaignHash::from_bytes([3; 32]),
            },
            "original",
            None,
        )
        .expect("same moved domain");
        let ChoiceDomain::Discrete(after) = owner.as_domain() else {
            panic!("same discrete domain");
        };

        assert_eq!(
            label_before,
            after
                .alternatives()
                .first_key_value()
                .expect("retained alternative")
                .1
                .label()
                .as_ptr()
        );
        println!(
            "owned-domain-geometry domain_size={} domain_align={} owner_size={} owner_align={} identity_size={} semantic_identity_size={}",
            std::mem::size_of::<ChoiceDomain>(),
            std::mem::align_of::<ChoiceDomain>(),
            std::mem::size_of::<ImmutableChoiceDomain>(),
            std::mem::align_of::<ImmutableChoiceDomain>(),
            std::mem::size_of::<ChoiceDomainId>(),
            std::mem::size_of::<ChoiceDomainSemanticId>()
        );
    }
}
