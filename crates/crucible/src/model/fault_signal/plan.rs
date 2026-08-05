//! Canonical scenario ownership for signal-driven fault programs and bindings.
//!
//! A [`FaultSignalPlan`] is the sole scenario-level container for executable
//! fault causes. It admits already-validated signal programs and bindings,
//! rejects cross-program or duplicate identities, and derives one content
//! address over the complete executable contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};

use super::*;

/// Maximum distinct signal programs in one scenario.
pub const HARD_FAULT_SIGNAL_PROGRAM_LIMIT: usize = 16_384;

/// Canonical, immutable signal-driven fault layer for one scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultSignalPlan {
    programs: Vec<SignalProgram>,
    bindings: Vec<FaultBinding>,
    id: ContentHash,
}

impl Default for FaultSignalPlan {
    fn default() -> Self {
        Self::empty()
    }
}

impl FaultSignalPlan {
    /// Builds the empty fault layer.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            programs: Vec::new(),
            bindings: Vec::new(),
            id: ContentHash::from_canonical_material(
                "crucible.fault-signal-plan.v1",
                "programs=0\nbindings=0",
            ),
        }
    }

    /// Validates, canonicalizes, and addresses complete executable contracts.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalPlanError`] for excessive or duplicate programs or
    /// bindings, a binding admitted against an absent program, or canonical
    /// binding encoding failure.
    pub fn new(
        mut programs: Vec<SignalProgram>,
        mut bindings: Vec<FaultBinding>,
    ) -> Result<Self, FaultSignalPlanError> {
        if programs.len() > HARD_FAULT_SIGNAL_PROGRAM_LIMIT {
            return Err(FaultSignalPlanError::TooManyPrograms {
                actual: programs.len(),
                hard: HARD_FAULT_SIGNAL_PROGRAM_LIMIT,
            });
        }
        if bindings.len() > HARD_FAULT_BINDING_LIMIT {
            return Err(FaultSignalPlanError::TooManyBindings {
                actual: bindings.len(),
                hard: HARD_FAULT_BINDING_LIMIT,
            });
        }
        programs.sort_by_key(SignalProgram::id);
        if programs.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(FaultSignalPlanError::DuplicateProgram);
        }
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        if bindings.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(FaultSignalPlanError::DuplicateBinding);
        }
        let program_ids = programs
            .iter()
            .map(SignalProgram::id)
            .collect::<BTreeSet<_>>();
        if let Some(binding) = bindings
            .iter()
            .find(|binding| !program_ids.contains(&binding.program()))
        {
            return Err(FaultSignalPlanError::MissingProgram {
                binding: binding.id().clone(),
                program: binding.program(),
            });
        }
        let mut material = format!("programs={}\nbindings={}", programs.len(), bindings.len());
        for program in &programs {
            material.push_str("\nprogram=");
            material.push_str(&program.id().to_hex());
        }
        for binding in &bindings {
            let digest = binding
                .contract_digest()
                .map_err(FaultSignalPlanError::BindingCodec)?;
            material.push_str("\nbinding=");
            material.push_str(binding.id().as_str());
            material.push(':');
            material.push_str(&digest.to_hex());
        }
        Ok(Self {
            programs,
            bindings,
            id: ContentHash::from_canonical_material("crucible.fault-signal-plan.v1", &material),
        })
    }

    /// Returns the fault-layer content identity.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns signal programs in canonical content-identity order.
    #[must_use]
    pub fn programs(&self) -> &[SignalProgram] {
        &self.programs
    }

    /// Returns bindings in canonical authored-identity order.
    #[must_use]
    pub fn bindings(&self) -> &[FaultBinding] {
        &self.bindings
    }

    /// Returns bindings grouped by their exact admitted program identity.
    #[must_use]
    pub fn bindings_by_program(&self) -> BTreeMap<ContentHash, Vec<&FaultBinding>> {
        let mut grouped = BTreeMap::<_, Vec<_>>::new();
        for binding in &self.bindings {
            grouped.entry(binding.program()).or_default().push(binding);
        }
        grouped
    }

    /// Returns every fine-grained production capability required at admission.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalPlanError::Capability`] if a registry capability
    /// constant violates the canonical capability-ID grammar.
    pub fn required_capabilities(
        &self,
    ) -> Result<BTreeSet<FaultCapabilityId>, FaultSignalPlanError> {
        self.bindings
            .iter()
            .map(|binding| {
                FaultCapabilityId::parse(binding.effect().capability())
                    .map_err(FaultSignalPlanError::Capability)
            })
            .collect()
    }
}

impl Hash for FaultSignalPlan {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Failure to admit a scenario's complete signal-driven fault layer.
#[derive(Debug)]
pub enum FaultSignalPlanError {
    /// Program count exceeds the implementation-owned hard ceiling.
    TooManyPrograms {
        /// Submitted count.
        actual: usize,
        /// Compiled ceiling.
        hard: usize,
    },
    /// Binding count exceeds the implementation-owned hard ceiling.
    TooManyBindings {
        /// Submitted count.
        actual: usize,
        /// Compiled ceiling.
        hard: usize,
    },
    /// Two submitted programs have the same content identity.
    DuplicateProgram,
    /// Two submitted bindings reuse one authored binding identity.
    DuplicateBinding,
    /// A binding was admitted against a program absent from this plan.
    MissingProgram {
        /// Authored binding identity.
        binding: FaultObjectId,
        /// Missing content-addressed program identity.
        program: ContentHash,
    },
    /// Canonical binding encoding failed.
    BindingCodec(serde_json::Error),
    /// A compiled registry capability ID was malformed.
    Capability(FaultContractError),
}

impl fmt::Display for FaultSignalPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault signal plan admission failed: {self:?}")
    }
}

impl Error for FaultSignalPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BindingCodec(error) => Some(error),
            Self::Capability(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "plan_test.rs"]
mod tests;
