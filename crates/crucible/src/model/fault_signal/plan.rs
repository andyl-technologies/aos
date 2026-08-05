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
use std::io;

use super::*;

/// Exact maximum signal graphs in one scenario plan.
///
/// Public v2 authoring owns one flat `plan.signal` graph. Independent physical
/// causes are disconnected components in that graph rather than separately
/// addressable program containers.
pub const HARD_FAULT_SIGNAL_PROGRAM_LIMIT: usize = 1;
/// Maximum deterministic persistence bytes for one admitted fault layer.
pub const HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES: usize = 256 * 1024 * 1024;

/// Canonical, immutable signal-driven fault layer for one scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultSignalPlan {
    programs: Vec<SignalProgram>,
    bindings: Vec<FaultBinding>,
    id: ContentHash,
    wire_bytes: Vec<u8>,
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
            wire_bytes: b"{\"semantic_version\":1,\"signal_program\":[],\"fault_binding\":[]}"
                .to_vec(),
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
        programs.sort_by_key(SignalProgram::id);
        if programs.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(FaultSignalPlanError::DuplicateProgram);
        }
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
        let mut plan = Self {
            programs,
            bindings,
            id: ContentHash::from_canonical_material("crucible.fault-signal-plan.v1", &material),
            wire_bytes: Vec::new(),
        };
        plan.wire_bytes = encode_wire_bounded(
            &FaultSignalPlanWire::from_plan(&plan),
            HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES,
        )
        .map_err(FaultSignalPlanError::WireCodec)?;
        Ok(plan)
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

    /// Returns the versioned deterministic persistence bytes.
    #[must_use]
    pub(crate) fn wire_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    /// Decodes and re-admits versioned deterministic persistence bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalPlanDecodeError`] for malformed JSON or any wire
    /// contract that fails semantic admission.
    pub(crate) fn from_wire_bytes(bytes: &[u8]) -> Result<Self, FaultSignalPlanDecodeError> {
        if bytes.len() > HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES {
            return Err(FaultSignalPlanDecodeError::WireLimit {
                actual: bytes.len(),
                hard: HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES,
            });
        }
        serde_json::from_slice::<FaultSignalPlanWire>(bytes)
            .map_err(FaultSignalPlanDecodeError::Json)?
            .admit()
            .map_err(FaultSignalPlanDecodeError::Admission)
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
    /// Complete plan persistence encoding failed.
    WireCodec(serde_json::Error),
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
            Self::WireCodec(error) => Some(error),
            Self::Capability(error) => Some(error),
            _ => None,
        }
    }
}

/// Failure to parse or semantically admit persisted fault-signal bytes.
#[derive(Debug)]
pub(crate) enum FaultSignalPlanDecodeError {
    /// The encoded plan exceeds the compiled persistence bound.
    WireLimit {
        /// Submitted byte count.
        actual: usize,
        /// Compiled byte ceiling.
        hard: usize,
    },
    /// JSON syntax or structural decoding failed.
    Json(serde_json::Error),
    /// The decoded contract failed semantic admission.
    Admission(FaultSignalWireError),
}

impl fmt::Display for FaultSignalPlanDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WireLimit { actual, hard } => write!(
                formatter,
                "fault signal plan wire bytes {actual} exceed hard limit {hard}"
            ),
            Self::Json(error) => write!(formatter, "decode fault signal plan JSON: {error}"),
            Self::Admission(error) => error.fmt(formatter),
        }
    }
}

impl Error for FaultSignalPlanDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::WireLimit { .. } => None,
            Self::Json(error) => Some(error),
            Self::Admission(error) => Some(error),
        }
    }
}

struct BoundedWireWriter {
    bytes: Vec<u8>,
    hard: usize,
}

impl io::Write for BoundedWireWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("fault signal wire length overflow"))?;
        if next > self.hard {
            return Err(io::Error::other(
                "fault signal wire exceeds compiled byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_wire_bounded<T: serde::Serialize>(
    value: &T,
    hard: usize,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut writer = BoundedWireWriter {
        bytes: Vec::new(),
        hard,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}

#[cfg(test)]
#[path = "plan_test.rs"]
mod tests;
