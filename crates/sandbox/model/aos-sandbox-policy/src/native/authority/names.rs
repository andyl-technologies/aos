//! Selects the Authority's existing finite recipes on the shared native owner.

use std::error::Error;

use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use super::RootAuthorityErrorV1;
use crate::native::RootPolicyNameObservationOriginalV1;
use crate::native::journal::RootPolicyJournalV1;
use crate::native::journal::names::{RootFixedNameRecipeV1, RootFixedNameRoleV1};

#[derive(Clone, Copy)]
pub(super) enum RootAuthorityNameRecipeV1 {
    Owner,
    Physical,
    NamesOnly,
}

impl RootAuthorityNameRecipeV1 {
    fn common(self) -> RootFixedNameRecipeV1 {
        match self {
            Self::Owner => RootFixedNameRecipeV1::Owner,
            Self::Physical => RootFixedNameRecipeV1::Physical,
            Self::NamesOnly => RootFixedNameRecipeV1::NamesOnly,
        }
    }
}

pub(super) struct RootAuthorityNamesOriginalV1 {
    original: RootPolicyNameObservationOriginalV1,
}

impl RootAuthorityNamesOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            original: RootPolicyNameObservationOriginalV1::new(),
        }
    }

    pub(super) fn fixed_demand_v1(
        recipe: RootAuthorityNameRecipeV1,
    ) -> Result<ResourceVector, RootAuthorityErrorV1> {
        Ok(RootPolicyNameObservationOriginalV1::additional_demand_v1(
            RootFixedNameRoleV1::Authority,
            recipe.common(),
        )?)
    }

    pub(super) fn observe_once(
        &mut self,
        journal: &RootPolicyJournalV1,
        recipe: RootAuthorityNameRecipeV1,
    ) -> Result<(), ()> {
        self.original
            .observe_once(journal, RootFixedNameRoleV1::Authority, recipe.common())
    }

    pub(super) fn settle_positive_once_v1(&mut self) {
        self.original.settle_positive_once_v1();
    }

    pub(super) fn names(&self) -> Option<ProtectedJournalNamesV1> {
        self.original.names()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

crate::native::journal::names::fixed_root_name_role_v1!(super::RootAuthorityOriginalV1, Authority);
