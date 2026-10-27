//! Observes both genuine current writers and their independently owed locations.
//!
//! Ready and issuer capture share this finite native bookend. The caller lends
//! the same private bare pair and original Open; historical rows or names DATA
//! cannot construct this owner or substitute its actual native observations.

use std::error::Error;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use crate::native::journal::{RootPolicyJournalV1, names::{
    RootFixedNameRecipeV1 as Recipe, RootFixedNameRoleV1 as Role,
    RootPolicyNameObservationOriginalV1 as Names,
}};
use crate::native::target::RootPolicyTargetOriginalV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;

use super::initial_open::{RootInitialOpenErrorV1 as E,
    RootInitialOpenPreparedOriginalV1, observe_names_v1};

type NamesResult = Option<Result<ProtectedJournalNamesV1, E>>;

pub(super) struct RootInitialWriterSampleOriginalV1 {
    authority_physical: Names,
    policy_physical: Names,
    authority_location: Names,
    policy_location: Names,
    authority_names: NamesResult,
    policy_names: NamesResult,
    names_binding: Option<Result<(), E>>,
    authority_post: Option<Result<(), E>>,
    policy_post: Option<Result<(), E>>,
    entered: bool,
    closed: bool,
}

impl RootInitialWriterSampleOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            authority_physical: Names::new(),
            policy_physical: Names::new(),
            authority_location: Names::new(),
            policy_location: Names::new(),
            authority_names: None,
            policy_names: None,
            names_binding: None,
            authority_post: None,
            policy_post: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn capture_once_v1(
        &mut self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.authority_names = Some(observe_names_v1(authority, Role::Authority,
            Recipe::Physical, &mut self.authority_physical));
        self.policy_names = Some(policy.observe_held_physical_names_once_v1(&mut self.policy_physical)
            .map_err(|()| E::Boundary));
        self.names_binding = Some((|| {
            let body = open.body_v1()?;
            if *positive(&self.authority_names)? != body.authority_names
                || *positive(&self.policy_names)? != body.policy_names
            {
                return Err(E::Boundary);
            }
            Ok(())
        })());

        // Both actual location observations remain independently owed after
        // either physical names or the original binding comparison refuses.
        self.authority_post = Some(self.authority_location
            .observe_once(authority, Role::Authority, Recipe::Location)
            .map_err(|()| E::Boundary));
        self.policy_post = Some(policy.observe_fixed_location_once_v1(&mut self.policy_location)
            .map_err(|()| E::Boundary));
    }

    pub(super) fn refuse_pair_v1(&mut self, error: aos_sandbox_broker::receiving::RootObservationErrorV1) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.authority_post = Some(Err(E::Root(error)));
        self.policy_post = Some(Err(E::Boundary));
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if !self.entered || self.closed {
            return Err(E::Boundary);
        }
        positive(&self.authority_names)?;
        positive(&self.policy_names)?;
        positive(&self.names_binding)?;
        positive(&self.authority_post)?;
        positive(&self.policy_post).map(|_| ())
    }

    pub(super) fn additional_native_demand_v1() -> Result<ResourceVector, NativeError> {
        let mut names = ResourceVector::ZERO;
        for (role, recipe) in [
            (Role::Authority, Recipe::Physical),
            (Role::Policy, Recipe::Physical),
            (Role::Authority, Recipe::Location),
            (Role::Policy, Recipe::Location),
        ] {
            names = names.checked_add(Names::additional_demand_v1(role, recipe)?)
                .map_err(|_| NativeError::geometry())?;
        }
        let cells = Names::retained_control_cells_v1().checked_mul(4)
            .ok_or_else(NativeError::geometry)?;
        names = names.checked_add(ResourceVector::ZERO.with(D::MetadataEntries, cells))
            .map_err(|_| NativeError::geometry())?;
        Ok(names)
    }

    pub(super) fn construction_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        let names = usize::try_from(Names::fixed_carrier_demand_v1()?
            .get(D::MemoryBytes)).ok()?.checked_mul(4)?;
        let constructors = size_of::<Self>().checked_mul(2)?.checked_add(names)?;
        let interfaces = size_of::<(&mut Self, &RootPolicyJournalV1,
            &RootPolicyTargetOriginalV1, &RootInitialOpenPreparedOriginalV1)>()
            .checked_mul(3)?
            .checked_add(size_of::<(&mut Self,
                aos_sandbox_broker::receiving::RootObservationErrorV1)>().checked_mul(3)?)?
            .checked_add(size_of::<&Self>().checked_mul(12)?)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(9)?)?
            .checked_add(size_of::<Result<ProtectedJournalNamesV1, E>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), ()>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<&ProtectedJournalNamesV1, E>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<&(), E>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(9)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(27)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)?;
        let quote_locals = size_of::<([(Role, Recipe); 4],
            std::array::IntoIter<(Role, Recipe), 4>, Option<(Role, Recipe)>,
            ResourceVector, u64)>().checked_mul(3)?;
        let captures = size_of::<(&Self, &RootInitialOpenPreparedOriginalV1)>()
            .checked_mul(3)?
            .checked_add(size_of::<&Self>().checked_mul(21)?)?;

        constructors.checked_add(interfaces)?
            .checked_add(quote_locals)?
            .checked_add(captures)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.authority_physical.failure()
            .or_else(|| cause(&self.authority_names))
            .or_else(|| self.policy_physical.failure())
            .or_else(|| cause(&self.policy_names))
            .or_else(|| cause(&self.names_binding))
            .or_else(|| self.authority_location.failure())
            .or_else(|| cause(&self.authority_post))
            .or_else(|| self.policy_location.failure())
            .or_else(|| cause(&self.policy_post))
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Boundary)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
