//! Retains ordinary Value construction from one actual immutable flat source.
//!
//! Taking the real effective-text owner preserves its upstream Ordinary/RawValue
//! semantics. This layer copies completed data without another parser pass.
//! Every deep partial is owned before effects and retires through a reserved bank.

use super::*;
use serde_json::Map;
use std::mem::size_of;

#[path = "materialize_value/constructors.rs"]
mod constructors;

#[path = "materialize_value/engine.rs"]
mod engine;
#[path = "materialize_value/retirement.rs"]
mod retirement;
#[path = "materialize_value/storage.rs"]
mod storage;

#[cfg(test)]
#[path = "materialize_value/tests.rs"]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Taking,
    Taken,
    Quoting,
    Quoted,
    Running,
    Complete,
    Failed,
}

enum Destination {
    Root,
    Array { frame: usize, slot: usize },
    Object { frame: usize, key: String },
}

enum Work {
    Visit {
        node: usize,
        destination: Destination,
    },
    Finish {
        frame: usize,
    },
}

enum Container {
    Array(Vec<Value>),
    Object(Map<String, Value>),
}

struct BuildFrame {
    destination: Destination,
    container: Container,
}

/// Owns the same flat input and every ordinary Value partial through refusal.
///
/// No mutable Value or bare owned output escapes this guard. A future caller
/// independently admits take/prewalk and the complete stored row before run.
/// Completion supplies neither Source authority nor native permission.
pub(crate) struct NativeImport18GuardedValueAttemptData {
    stage: Stage,
    source: Option<NativeImport18EffectiveTextAttemptData>,
    row: Option<storage::ConstructionData>,
    root: Option<Value>,
    pending: Option<Value>,
    pending_old: Option<Value>,
    destination: Option<Destination>,
    key: Option<String>,
    work: Vec<Work>,
    frames: Vec<BuildFrame>,
    retirement: Vec<Value>,
    steps: usize,
    string_bytes: usize,
    array_bytes: usize,
    tree_members: usize,
    tree_containers: usize,
    #[cfg(test)]
    fail_after: Option<usize>,
    #[cfg(test)]
    panic_after: Option<usize>,
}

impl NativeImport18GuardedValueAttemptData {
    /// Names actual empty-owner take R/T/S before moving the same input.
    ///
    /// Source backing remains independently retained. Moving it never renews
    /// its original debit. Keep this fixed S available during quote_into_data.
    ///
    /// # Errors
    /// Refuses incompatible constructor geometry or checked row overflow.
    pub(crate) fn take_requested_storage_data() -> Result<[usize; 3], ProviderError> {
        storage::take_requested_storage_data()
    }

    /// Installs a spent owner before taking and checking the actual flat input.
    ///
    /// # Errors
    /// Refuses reuse, missing input or incomplete source. Every moved input
    /// stays under the same failed output; no retry slot is manufactured.
    pub(crate) fn take_into_data(
        source: &mut Option<NativeImport18EffectiveTextAttemptData>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            stage: Stage::Taking,
            source: None,
            row: None,
            root: None,
            pending: None,
            pending_old: None,
            destination: None,
            key: None,
            work: Vec::new(),
            frames: Vec::new(),
            retirement: Vec::new(),
            steps: 0,
            string_bytes: 0,
            array_bytes: 0,
            tree_members: 0,
            tree_containers: 0,
            #[cfg(test)]
            fail_after: None,
            #[cfg(test)]
            panic_after: None,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.source = source.take();
        let result = owner
            .source
            .as_ref()
            .ok_or_else(invalid)
            .and_then(|source| source.completed_data().map(|_| ()));
        owner.stage = if result.is_ok() {
            Stage::Taken
        } else {
            Stage::Failed
        };
        result
    }

    /// Stores the actual private input's prospective constructor row once.
    ///
    /// The caller first admits fixed take/prewalk S beside every old owner.
    /// It releases this loan and admits the returned full axes before run.
    ///
    /// # Errors
    /// Refuses reuse, incomplete source, overflow or excessive demand.
    pub(crate) fn quote_into_data(&mut self, maximum: usize) -> Result<[usize; 3], ProviderError> {
        if self.stage != Stage::Taken || self.row.is_some() {
            return Err(invalid());
        }
        self.stage = Stage::Quoting;
        let result = self.quote_row_data(maximum);
        self.stage = if result.is_ok() {
            Stage::Quoted
        } else {
            Stage::Failed
        };
        result
    }

    fn quote_row_data(&mut self, maximum: usize) -> Result<[usize; 3], ProviderError> {
        let source = self.source.as_ref().ok_or_else(invalid)?;
        source.completed_data()?;
        let row = storage::ConstructionData::quote_data(source, maximum)?;
        let requested = row.requested;
        self.row = Some(row);
        Ok(requested)
    }

    /// Constructs from the retained row after the caller's real admission.
    ///
    /// No feature switch, external numeric grant or replacement source enters
    /// this operation. Failed state and all partial allocations remain owned.
    ///
    /// # Errors
    /// Refuses reuse, reserve/capacity or internal constructor mismatch.
    pub(crate) fn run_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        self.stage = Stage::Running;
        let result = self.materialize_data();
        self.stage = if result.is_ok() {
            Stage::Complete
        } else {
            Stage::Failed
        };
        result
    }

    /// Borrows the real output while its retirement owner remains live.
    ///
    /// Consumers independently fund any serializer or adapter they invoke.
    /// No mutable view, deep Clone or ordinary owned transfer is supplied.
    ///
    /// # Errors
    /// Refuses incomplete or failed materialization.
    pub(crate) fn completed_data(&self) -> Result<&Value, ProviderError> {
        if self.stage != Stage::Complete {
            return Err(invalid());
        }
        self.root.as_ref().ok_or_else(invalid)
    }

    /// Counts the original input and every initialized output/work capacity.
    ///
    /// # Errors
    /// Refuses source census, layout overflow or the same finite bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        storage::retained_storage_data(self, maximum)
    }
}

fn invalid() -> ProviderError {
    ProviderError::Frame("explicit18 guarded flat Value construction")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("explicit18 guarded flat Value workspace")
}
