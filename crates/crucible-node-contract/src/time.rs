//! Checked superdense coordinates and regular coordinator boundary grids.
//!
//! ```json
//! { "time_ps": "100", "microstep": "1", "phase": 2 }
//! ```

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ContentRef, ContractError, Id, Tick, U64, Validate, invalid};

/// Orders public work within one superdense microstep.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u16)]
pub enum Phase {
    /// Applies coordinator boundary controls.
    BoundaryControl = 0,
    /// Publishes previously produced output.
    Publication = 1,
    /// Delivers canonically staged input.
    Delivery = 2,
    /// Executes semantic reactions and independent alarms.
    Reaction = 3,
}

impl Serialize for Phase {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(*self as u16)
    }
}

impl<'de> Deserialize<'de> for Phase {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u16::deserialize(deserializer)? {
            0 => Ok(Self::BoundaryControl),
            1 => Ok(Self::Publication),
            2 => Ok(Self::Delivery),
            3 => Ok(Self::Reaction),
            _ => Err(serde::de::Error::custom("unsupported superdense phase")),
        }
    }
}

/// Locates public work on the superdense-v1 coordinator timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    /// Measures the modeled instant in picoseconds.
    pub time_ps: Tick,
    /// Orders causal same-time reactions without advancing modeled time.
    pub microstep: U64,
    /// Orders control, publication, delivery, and reaction within a microstep.
    pub phase: Phase,
}

impl Position {
    /// Constructs a position from checked integer components.
    pub const fn new(time_ps: Tick, microstep: U64, phase: Phase) -> Self {
        Self {
            time_ps,
            microstep,
            phase,
        }
    }

    /// Locates a same-time publication caused by work at this position.
    ///
    /// # Errors
    /// Rejects microstep overflow and a publication outside the admitted count.
    pub fn reaction_publication(self, maximum_microsteps: U64) -> Result<Self, ContractError> {
        let microstep = self.microstep.checked_add(U64::new(1))?;
        if microstep >= maximum_microsteps {
            return Err(invalid("microstep", "same-time closure limit exceeded"));
        }
        Ok(Self {
            microstep,
            phase: Phase::Publication,
            ..self
        })
    }
}

impl Validate for Position {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Defines the deterministic global order without replacing native event order.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EventKey {
    /// Orders the modeled instant, causal microstep, and public phase.
    pub position: Position,
    /// Breaks ties by consumer ASCII identity.
    pub consumer_node_id: Id,
    /// Breaks ties by producer ASCII identity.
    pub producer_node_id: Id,
    /// Orders the producer's unique public sequence.
    pub source_sequence: U64,
}

/// Identifies one logical node port lane.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Selects the admitted logical node.
    pub node_id: Id,
    /// Selects its stable port.
    pub port_id: Id,
    /// Selects the input or output lane.
    pub lane_id: Id,
}

impl Validate for Endpoint {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Describes the scope of an output lower bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundKind {
    /// Permits output at equality.
    At,
    /// Excludes output at equality.
    After,
    /// Excludes output until separately authorized activation.
    NoneUntilActivation,
    /// Provides no positive lookahead.
    Unknown,
}

/// Carries a lower-bound claim requiring separately qualified evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    /// Selects the exact equality and activation semantics.
    pub kind: BoundKind,
    /// Locates an `at` or `after` bound; otherwise explicitly null.
    #[serde(deserialize_with = "crate::schema::required_nullable")]
    pub position: Option<Position>,
    /// Binds proof content; unknown bounds have no evidence.
    #[serde(deserialize_with = "crate::schema::required_nullable")]
    pub evidence: Option<ContentRef>,
}

impl Validate for Bound {
    fn validate(&self) -> Result<(), ContractError> {
        let valid = match self.kind {
            BoundKind::At | BoundKind::After => self.position.is_some() && self.evidence.is_some(),
            BoundKind::NoneUntilActivation => self.position.is_none() && self.evidence.is_some(),
            BoundKind::Unknown => self.position.is_none() && self.evidence.is_none(),
        };
        if !valid {
            return Err(invalid("bound", "kind disagrees with position or evidence"));
        }
        if let Some(evidence) = &self.evidence {
            evidence.validate()?;
        }
        Ok(())
    }
}

/// Defines representable boundaries as `phase + index * quantum`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuantumGrid {
    quantum: U64,
    phase: U64,
}

impl QuantumGrid {
    /// Constructs a positive regular grid with phase smaller than quantum.
    ///
    /// # Errors
    /// Rejects a zero quantum or a phase at or beyond the quantum.
    pub fn new(quantum: U64, phase: U64) -> Result<Self, ContractError> {
        if quantum.get() == 0 || phase >= quantum {
            return Err(invalid(
                "grid",
                "require positive quantum and phase < quantum",
            ));
        }
        Ok(Self { quantum, phase })
    }

    /// Returns the positive boundary spacing in picoseconds.
    pub const fn quantum(self) -> U64 {
        self.quantum
    }

    /// Returns the first representable boundary.
    pub const fn phase(self) -> U64 {
        self.phase
    }

    /// Calculates a boundary without rounding or saturation.
    ///
    /// # Errors
    /// Rejects multiplication or addition overflow.
    pub fn boundary(self, index: U64) -> Result<Tick, ContractError> {
        self.phase.checked_add(index.checked_mul(self.quantum)?)
    }

    /// Returns the last boundary at or before an instant.
    ///
    /// # Errors
    /// Returns an error if the instant precedes the first boundary.
    pub fn predecessor(self, instant: Tick) -> Result<Tick, ContractError> {
        let delta = instant
            .get()
            .checked_sub(self.phase.get())
            .ok_or_else(|| invalid("instant", "before grid phase"))?;
        self.boundary(U64::new(delta / self.quantum.get()))
    }

    /// Returns the first boundary at or after an instant.
    ///
    /// # Errors
    /// Rejects a boundary beyond the timeline's integer range.
    pub fn successor(self, instant: Tick) -> Result<Tick, ContractError> {
        if instant <= self.phase {
            return Ok(self.phase);
        }
        let delta = instant.get() - self.phase.get();
        let quotient = delta / self.quantum.get();
        let index = quotient
            .checked_add(u64::from(!delta.is_multiple_of(self.quantum.get())))
            .ok_or(ContractError::Overflow)?;
        self.boundary(U64::new(index))
    }

    /// Reports whether an instant is exactly representable on this grid.
    pub fn contains(self, instant: Tick) -> bool {
        instant
            .get()
            .checked_sub(self.phase.get())
            .is_some_and(|delta| delta.is_multiple_of(self.quantum.get()))
    }
}
