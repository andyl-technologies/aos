//! Retains finite fixed Root location, names and physical-witness observations.
//!
//! The role owns these finite destinations before entering the existing lower
//! samplers. A readonly native view keeps the original selected invocation fence
//! over each native operation; an ordinary fixed owner uses its same actual
//! files. No supplied file, path, map, financial handle or witness is adopted.

use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::journal::RootPolicyJournalV1;

const DIRECTORY: &str = "/var/lib/aos/sandbox/policy-compiler";

#[derive(Clone, Copy)]
pub(in crate::native) enum RootFixedNameRoleV1 {
    Authority,
    Policy,
}

impl RootFixedNameRoleV1 {
    fn name(self) -> &'static str {
        match self {
            Self::Authority => "authority.journal",
            Self::Policy => "state.journal",
        }
    }

    fn limits(self) -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits {
        match self {
            Self::Authority => {
                aos_sandbox_broker::receiving::root_authority_journal_limits_data_v1()
            }
            Self::Policy => Default::default(),
        }
    }
}

// These are the finite reached existing native recipes. Selecting comparison
// work is not a role capability and cannot select an arbitrary native target.
#[derive(Clone, Copy)]
pub(in crate::native) enum RootFixedNameRecipeV1 {
    Owner,
    Location,
    Physical,
    NamesOnly,
    // Basenames only, without another health sample or physical witness.
    PlainNames,
    // The original startup final post names first, then fixed location.
    StartupFinal,
}

/// Retains one reached fixed Root observation and its actual first cause.
///
/// The currentness original precedes the witness in field/drop order, matching
/// the existing adjacent caller destinations. A genuine Authority or Target
/// method selects the fixed native recipe; no caller supplies a pathname,
/// native view, UID, writer or proof of successful observation.
pub struct RootPolicyNameObservationOriginalV1 {
    currentness: WriterCurrentnessOriginalsV1<Mechanical>,
    witness: WriterWitnessOriginalsV1<Mechanical>,
    entry: Option<Result<(), PolicyNativeJournalErrorV1>>,
    health: Option<Result<(), PolicyNativeJournalErrorV1>>,
    observed: Option<Result<(), Mechanical>>,
    witnessed: Option<Result<(), Mechanical>>,
    names: Option<ProtectedJournalNamesV1>,
    reentry: Option<PolicyNativeJournalErrorV1>,
    entered: bool,
    recipe: Option<RootFixedNameRecipeV1>,
}

impl RootPolicyNameObservationOriginalV1 {
    /// Constructs inert destinations without observing or granting an owner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            currentness: WriterCurrentnessOriginalsV1::new(),
            witness: WriterWitnessOriginalsV1::new(),
            entry: None,
            health: None,
            observed: None,
            witnessed: None,
            names: None,
            reentry: None,
            entered: false,
            recipe: None,
        }
    }

    /// Measures constructor and return headers beyond the caller's resident field.
    ///
    /// The enclosing caller includes the resident field in its compiled whole
    /// state and separately pays reached fixed-path/name/witness backing. This
    /// supplier grants no native or financial admission.
    #[must_use]
    pub fn fixed_carrier_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Measures the additional return plane of this owner's `Default` forwarding.
    ///
    /// Actual `Default::default` calls add this one header to the direct
    /// constructor supplier; direct `new` calls do not. Moving the same owner
    /// adds no namespace entry or duplicate retained-control identity.
    #[must_use]
    pub fn default_forwarding_demand_v1() -> Option<ResourceVector> {
        let bytes = u64::try_from(std::mem::size_of::<Self>()).ok()?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Counts this owner's eight separately retained control identities.
    ///
    /// The cells are entry, health, observed, witnessed, names, reentry,
    /// entered and recipe. The actual upper retained-cell model consumes this
    /// count once per observation owner. Native path/name namespace backing
    /// and the two original sink owners remain separate, as do memory bytes.
    /// This count is independent of native layout size and grants no budget.
    #[must_use]
    pub const fn retained_control_cells_v1() -> u64 {
        8
    }

    pub(in crate::native) fn additional_demand_v1(
        role: RootFixedNameRoleV1,
        recipe: RootFixedNameRecipeV1,
    ) -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        let geometry = || PolicyNativeJournalErrorV1::geometry();
        let actual = match recipe {
            RootFixedNameRecipeV1::Owner
            | RootFixedNameRecipeV1::Location
            | RootFixedNameRecipeV1::StartupFinal => {
                WriterCurrentnessOriginalsV1::<Mechanical>::fixed_demand_v1(
                    Path::new(DIRECTORY),
                    role.name(),
                )?
            }
            RootFixedNameRecipeV1::Physical
            | RootFixedNameRecipeV1::NamesOnly
            | RootFixedNameRecipeV1::PlainNames => {
                WriterCurrentnessOriginalsV1::<Mechanical>::named_demand_v1(role.name())?
            }
        };
        // The enclosing original already owns this inline destination. The
        // lower observation supplier includes one such currentness header;
        // remove only that embedded header, retaining all native backing.
        let current_header =
            u64::try_from(std::mem::size_of::<WriterCurrentnessOriginalsV1<Mechanical>>())
                .map_err(|_| geometry())?;
        let mut demand = actual
            .checked_sub(ResourceVector::ZERO.with(D::MemoryBytes, current_header))
            .map_err(|_| geometry())?;
        if matches!(recipe, RootFixedNameRecipeV1::Physical) {
            let witness = WriterWitnessOriginalsV1::<Mechanical>::receiving_footprint_v1()
                .ok_or_else(geometry)?;
            let headers = std::mem::size_of::<WriterWitnessOriginalsV1<Mechanical>>()
                .checked_mul(2)
                .ok_or_else(geometry)?;
            let bytes = witness
                .memory_bytes
                .checked_sub(headers)
                .ok_or_else(geometry)?;
            demand = demand
                .checked_add(ResourceVector::ZERO.with(
                    D::MemoryBytes,
                    u64::try_from(bytes).map_err(|_| geometry())?,
                ))
                .map_err(|_| geometry())?;
        }
        let controls = std::mem::size_of::<(&RootPolicyJournalV1, RootFixedNameRoleV1)>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), PolicyNativeJournalErrorV1>>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<bool>().checked_mul(12)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(geometry)?;
        demand = demand
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))
            .map_err(|_| geometry())?;
        if matches!(recipe, RootFixedNameRecipeV1::StartupFinal) {
            let bytes = Self::startup_final_control_bytes_v1()
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(geometry)?;
            demand = demand
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .map_err(|_| geometry())?;
        }
        Ok(demand)
    }

    // The complete genuine enclosing quote precedes construction. The entry
    // latch is set before the first observation, including an unreturned panic.
    // Caller-owned custody survives independent later role/native posts.
    pub(in crate::native) fn observe_once(
        &mut self,
        journal: &RootPolicyJournalV1,
        role: RootFixedNameRoleV1,
        recipe: RootFixedNameRecipeV1,
    ) -> Result<(), ()> {
        if self.entered {
            self.reentry
                .get_or_insert(PolicyNativeJournalErrorV1::boundary());
            return Err(());
        }
        self.entered = true;
        self.recipe = Some(recipe);
        let location_only = matches!(recipe, RootFixedNameRecipeV1::Location);
        self.entry = Some((|| {
            if location_only {
                // The old location-only method begins before fixed binding.
                self.currentness.begin(false)?;
            }
            if matches!(recipe, RootFixedNameRecipeV1::StartupFinal) {
                self.currentness.begin(true)?;
                return Ok(());
            }
            require_fixed_binding_v1(journal, role)
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(());
        }

        let owner = matches!(
            recipe,
            RootFixedNameRecipeV1::Owner | RootFixedNameRecipeV1::Location
        );
        self.observed = Some((|| {
            if !location_only && !matches!(recipe, RootFixedNameRecipeV1::StartupFinal) {
                self.currentness.begin(!owner)?;
            }
            let result = (|| {
                if matches!(recipe, RootFixedNameRecipeV1::StartupFinal) {
                    // This independent final duty observes names even after
                    // an earlier body refusal; health belongs after location.
                    journal
                        .read_view()
                        .observe_names_into(&mut self.currentness)?;
                    self.entry = Some(require_fixed_binding_v1(journal, role));
                    if !matches!(self.entry, Some(Ok(()))) {
                        return Err(Mechanical::ProtectedBoundary);
                    }
                    journal.read_view().observe_directory_binding_into(
                        Path::new(DIRECTORY),
                        0,
                        &mut self.currentness,
                    )?;
                    self.health = Some(journal.require_healthy_native());
                    return if matches!(self.health, Some(Ok(()))) {
                        Ok(())
                    } else {
                        Err(Mechanical::ProtectedBoundary)
                    };
                }
                if owner {
                    journal.read_view().observe_directory_binding_into(
                        Path::new(DIRECTORY),
                        0,
                        &mut self.currentness,
                    )?;
                    // Preserve the old directory-before-health frontier. This
                    // is a negative view of the same retained native owner.
                    self.health = Some(journal.require_healthy_native());
                    if !matches!(self.health, Some(Ok(()))) {
                        return Err(Mechanical::ProtectedBoundary);
                    }
                }
                if matches!(recipe, RootFixedNameRecipeV1::NamesOnly) {
                    // The old explicit validate-held-names method checks
                    // authority health before its names-only observation.
                    // The distinct physical owed-post recipe omits this gate.
                    self.health = Some(journal.require_healthy_native());
                    if !matches!(self.health, Some(Ok(()))) {
                        return Err(Mechanical::ProtectedBoundary);
                    }
                }
                if location_only {
                    Ok(())
                } else {
                    journal
                        .read_view()
                        .observe_names_into(&mut self.currentness)
                }
            })();
            self.currentness.finish(result)
        })());
        if !matches!(self.observed, Some(Ok(()))) {
            return Err(());
        }

        if matches!(recipe, RootFixedNameRecipeV1::Physical) {
            self.witnessed = Some(
                journal
                    .read_view()
                    .writer_witness_retaining_v1(&mut self.witness),
            );
            if !matches!(self.witnessed, Some(Ok(()))) {
                return Err(());
            }
            let Some(witness) = self.witness.completed_witness() else {
                self.reentry = Some(PolicyNativeJournalErrorV1::boundary());
                return Err(());
            };
            self.names = Some(ProtectedJournalNamesV1::from_historical_fields(
                witness.directory().physical_pair(),
                witness.file().physical_pair(),
                witness.lock().physical_pair(),
            ));
        }
        Ok(())
    }

    pub(in crate::native) fn observe_startup_final_ordinary_once_v1(
        &mut self,
        opening: &crate::native::journal::RootPolicyOrdinaryOpeningOriginalV1,
    ) -> Result<(), ()> {
        if let Some(journal) = opening.journal_v1() {
            return self.observe_once(
                journal,
                RootFixedNameRoleV1::Authority,
                RootFixedNameRecipeV1::StartupFinal,
            );
        }
        if self.entered {
            self.reentry
                .get_or_insert(PolicyNativeJournalErrorV1::boundary());
            return Err(());
        }
        self.entered = true;
        self.recipe = Some(RootFixedNameRecipeV1::StartupFinal);
        self.observed =
            Some(opening.observe_untransferred_startup_names_once_v1(&mut self.currentness));
        if matches!(self.observed, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn startup_final_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<(
            &mut Self,
            &crate::native::journal::RootPolicyOrdinaryOpeningOriginalV1,
        )>()
        .checked_mul(3)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), Mechanical>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), PolicyNativeJournalErrorV1>>().checked_mul(3)?)?
        .checked_add(
            size_of::<(
                &crate::native::journal::RootPolicyOrdinaryOpeningOriginalV1,
                &mut WriterCurrentnessOriginalsV1<Mechanical>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<Option<&RootPolicyJournalV1>>().checked_mul(3)?)
    }

    /// Copies physical names only from this same positive witness observation.
    ///
    /// This historical DATA performs no IO and establishes no currentness.
    #[must_use]
    pub fn names(&self) -> Option<ProtectedJournalNamesV1> {
        if self.failure().is_some() {
            return None;
        }
        self.names
    }

    /// Disposes fresh probes only after this whole actual recipe succeeded.
    ///
    /// Former nonretaining callers invoke this at their existing successful
    /// local-drop frontier. Failed and incomplete recipes keep every native
    /// prefix untouched. Historical names, compact outcomes and the entered
    /// latch stay resident; this admits no retry, funding refund or clearance.
    pub fn settle_positive_once_v1(&mut self) {
        if !self.entered
            || self.failure().is_some()
            || !matches!(self.entry, Some(Ok(())))
            || !matches!(self.observed, Some(Ok(())))
        {
            return;
        }
        let completed = match self.recipe {
            Some(RootFixedNameRecipeV1::Owner | RootFixedNameRecipeV1::Location) => {
                matches!(self.health, Some(Ok(())))
            }
            Some(RootFixedNameRecipeV1::Physical) => {
                matches!(self.witnessed, Some(Ok(()))) && self.names.is_some()
            }
            Some(RootFixedNameRecipeV1::NamesOnly) => matches!(self.health, Some(Ok(()))),
            Some(RootFixedNameRecipeV1::PlainNames) => true,
            Some(RootFixedNameRecipeV1::StartupFinal) => matches!(self.health, Some(Ok(()))),
            None => false,
        };
        if completed {
            self.currentness.settle_positive_once_v1();
            self.witness.retire_positive_metadata_once_v1();
        }
    }

    /// Borrows the actual first refused entry, native capture or health cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.entry
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| {
                self.health
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.currentness.failure())
            .or_else(|| {
                self.observed
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.witness.failure())
            .or_else(|| {
                self.witnessed
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.reentry.as_ref().map(|error| error as _))
    }
}

impl Default for RootPolicyNameObservationOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

// Expansion occurs only in each genuine fixed owner's private child. The
// lexical field loan keeps both forwarding surfaces on this one native driver.
macro_rules! fixed_root_name_role_v1 {
    ($owner:path, $role:ident) => {
        impl $owner {
            /// Measures reached fixed-location backing beyond inline sink fields.
            ///
            /// The caller separately pays its whole resident state, constructor
            /// and typed return carriers before the native observation.
            ///
            /// # Errors
            /// Refuses checked fixed-path representation overflow.
            pub fn location_observation_additional_demand_v1()
                -> Result<aos_sandbox_model::ResourceVector, $crate::native::PolicyNativeJournalErrorV1>
            {
                $crate::native::journal::names::RootPolicyNameObservationOriginalV1::additional_demand_v1(
                    $crate::native::journal::names::RootFixedNameRoleV1::$role,
                    $crate::native::journal::names::RootFixedNameRecipeV1::Location,
                )
            }

            /// Measures the fixed directory, health and names recipe backing.
            ///
            /// Inline owner fields and constructor/return carriers remain in
            /// the actual enclosing invoice before this observation is entered.
            ///
            /// # Errors
            /// Refuses checked fixed-directory or fixed-name geometry overflow.
            pub fn owned_names_additional_demand_v1()
                -> Result<aos_sandbox_model::ResourceVector, $crate::native::PolicyNativeJournalErrorV1>
            {
                $crate::native::journal::names::RootPolicyNameObservationOriginalV1::additional_demand_v1(
                    $crate::native::journal::names::RootFixedNameRoleV1::$role,
                    $crate::native::journal::names::RootFixedNameRecipeV1::Owner,
                )
            }

            /// Measures reached names and witness backing beyond inline sinks.
            ///
            /// The caller separately pays its whole resident state, constructor
            /// and typed return carriers before the native observation.
            ///
            /// # Errors
            /// Refuses checked fixed-name or native-witness geometry overflow.
            pub fn physical_names_additional_demand_v1()
                -> Result<aos_sandbox_model::ResourceVector, $crate::native::PolicyNativeJournalErrorV1>
            {
                $crate::native::journal::names::RootPolicyNameObservationOriginalV1::additional_demand_v1(
                    $crate::native::journal::names::RootFixedNameRoleV1::$role,
                    $crate::native::journal::names::RootFixedNameRecipeV1::Physical,
                )
            }

            /// Observes this actual fixed binding, fresh directory and then health.
            ///
            /// This location-only recipe does not observe lock or file names.
            /// The caller retains the supplied original through later posts.
            ///
            /// # Errors
            /// Returns a marker after retaining reentry, binding, native or
            /// health refusal in the same caller-owned original.
            pub fn observe_fixed_location_once_v1(
                &self,
                original: &mut $crate::native::RootPolicyNameObservationOriginalV1,
            ) -> Result<(), ()> {
                original.observe_once(
                    &self.journal,
                    $crate::native::journal::names::RootFixedNameRoleV1::$role,
                    $crate::native::journal::names::RootFixedNameRecipeV1::Location,
                )
            }

            /// Observes this fixed binding, fresh directory, health and then names.
            ///
            /// This is the existing whole owned-name recipe. It creates no
            /// physical witness or permission to skip independent later posts.
            ///
            /// # Errors
            /// Returns a marker after retaining the actual fixed binding,
            /// native, health, names or reentry refusal in this same original.
            pub fn observe_owned_names_once_v1(
                &self,
                original: &mut $crate::native::RootPolicyNameObservationOriginalV1,
            ) -> Result<(), ()> {
                original.observe_once(
                    &self.journal,
                    $crate::native::journal::names::RootFixedNameRoleV1::$role,
                    $crate::native::journal::names::RootFixedNameRecipeV1::Owner,
                )
            }

            /// Observes same held names first and then the retained physical witness.
            ///
            /// This owed observation adds no writer-health or admission gate.
            /// Positive names are historical DATA, not currentness or clearance.
            ///
            /// # Errors
            /// Returns a marker only after the actual native/name/witness or
            /// reentry cause is retained in the same supplied original.
            pub fn observe_held_physical_names_once_v1(
                &self,
                original: &mut $crate::native::RootPolicyNameObservationOriginalV1,
            ) -> Result<
                aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
                (),
            > {
                original.observe_once(
                    &self.journal,
                    $crate::native::journal::names::RootFixedNameRoleV1::$role,
                    $crate::native::journal::names::RootFixedNameRecipeV1::Physical,
                )?;
                original.names().ok_or(())
            }
        }
    };
}

pub(in crate::native) use fixed_root_name_role_v1;

fn require_fixed_binding_v1(
    journal: &RootPolicyJournalV1,
    role: RootFixedNameRoleV1,
) -> Result<(), PolicyNativeJournalErrorV1> {
    let view = journal.read_view();
    if view.protected_name() != Some(role.name())
        || view.protected_uid() != Some(0)
        || view.limits() != role.limits()
    {
        return Err(PolicyNativeJournalErrorV1::boundary());
    }
    Ok(())
}
