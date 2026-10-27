//! Retains the actual fixed normal application argv after genuine Source capture.
//!
//! The real PID1 Source producer checks argc2, the exact normal flag and its
//! materialized unit fragment before birth. The same measured profile supplies
//! the sole executable path. This recipient pays the two standard-library
//! argument copies and controls before collecting them; DATA cannot select
//! another argument table or reconstruct the initial Source.

use std::ffi::{OsStr, OsString};

use super::*;

const FLAG: &str = "--boot-preparation-v1";

pub(super) struct ArgumentsOriginal {
    arguments: Option<std::env::ArgsOs>,
    program: Option<OsString>,
    mode: Option<OsString>,
    extra: Option<OsString>,
    entered: bool,
    comparison: Option<Result<(), RuntimeBootPreparationStartupClosedV1>>,
}

impl ArgumentsOriginal {
    pub(super) fn new() -> Self {
        Self {
            arguments: None,
            program: None,
            mode: None,
            extra: None,
            entered: false,
            comparison: None,
        }
    }

    fn demand(executable: &str) -> Option<ResourceVector> {
        // Source's native PID1 gate already fixed application argc2 and the
        // complete canonical ExecStart. Four OsString cells dominate the two
        // VecDeque cells and their standard iterator/return staging copies;
        // actual resident owner controls are counted separately by size_of.
        let strings = executable.len().checked_add(FLAG.len())?.checked_mul(2)?;
        let cells = std::mem::size_of::<OsString>().checked_mul(4)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(cells)?
            .checked_add(strings)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?))
    }

    fn capture_once(
        &mut self,
        executable: &str,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if self.entered {
            return Err(RuntimeBootPreparationStartupClosedV1);
        }
        self.entered = true;
        self.arguments = Some(std::env::args_os());
        let arguments = self
            .arguments
            .as_mut()
            .ok_or(RuntimeBootPreparationStartupClosedV1)?;
        self.program = arguments.next();
        self.mode = arguments.next();
        self.extra = arguments.next();
        self.comparison = Some(
            if self.program.as_deref() == Some(OsStr::new(executable))
                && self.mode.as_deref() == Some(OsStr::new(FLAG))
                && self.extra.is_none()
            {
                Ok(())
            } else {
                Err(RuntimeBootPreparationStartupClosedV1)
            },
        );
        self.comparison
            .as_ref()
            .copied()
            .ok_or(RuntimeBootPreparationStartupClosedV1)?
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.comparison
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause as _)
    }
}

impl RuntimeBootPreparationStartupOriginalV1 {
    /// Prepays and compares the genuine Source producer's fixed application argv.
    ///
    /// Source capture precedes collection. Its native PID1 gate already fixes
    /// argc2, this exact normal mode and the complete measured unit fragment;
    /// the standard library's argument copies are priced from that same actual
    /// executable path and retained here through the final Source after.
    ///
    /// # Errors
    /// Refuses Source funding, changed executable/mode, repetition, extra args
    /// or absent positive startup admission. No fallback mode is attempted.
    pub fn require_arguments_once_v1(
        &mut self,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if !self.admitted || self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.closed);
        }
        if self.body.as_ref().ok_or(self.closed)?.arguments.entered {
            return Err(self.fail(First::Order));
        }
        let demand = ArgumentsOriginal::demand(
            &self
                .body
                .as_ref()
                .ok_or(self.closed)?
                .model()?
                .publisher
                .executable
                .path,
        );
        self.fund_additional(demand)?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        let model = body
            .decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        let result = body
            .arguments
            .capture_once(&model.publisher.executable.path);
        if result.is_err() {
            self.fail(First::Arguments);
        }
        result
    }
}
