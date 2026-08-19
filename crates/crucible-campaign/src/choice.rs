//! Typed choice domains, declarations, opportunities, groups, and selections.

mod domain;
mod group;
mod model;

pub use domain::{
    BooleanDomain, ChoiceDomain, ChoiceValue, DiscreteAlternative, DiscreteDomain, IntegerDomain,
    IntegerRepresentation, IntegerValue,
};
pub use group::{
    ChoiceGroup, ChoiceGroupApplication, ChoiceGroupDomain, ChoiceGroupValue,
    ChoiceRelationalConstraint, ChoiceTuple,
};
pub use model::{
    ChoiceClassContext, ChoiceCoordinate, ChoiceOpportunity, ChoiceSource, ModelSampleEvidence,
    ModelSampleVerifier, SelectableDeclaration, Selection, SelectionOrigin,
};
