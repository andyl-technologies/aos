//! Retains every node RAM leaf until its actual join and controller return.

use super::*;
use crate::ram_control::{RamControlRetirementHistory, RamControlRetirementProgress};
use crate::ram_source::{QemuRamSourceService, QemuRamSourceStopHistory};

#[derive(Debug)]
pub(super) struct RamCleanup {
    sources: [Option<QemuRamSourceStopHistory>; 3],
    stage: Option<Box<QemuNodeError>>,
    stage_latest: Option<Box<QemuNodeError>>,
    controllers: [Option<RamControlRetirementHistory>; 2],
    pub(super) retirement: [RamControlRetirementProgress; 2],
    entered: bool,
    unreported: bool,
}

impl RamCleanup {
    pub(super) const fn new() -> Self {
        Self {
            sources: [None, None, None],
            stage: None,
            stage_latest: None,
            controllers: [None, None],
            retirement: [
                RamControlRetirementProgress::new(),
                RamControlRetirementProgress::new(),
            ],
            entered: false,
            unreported: false,
        }
    }

    pub(super) fn entered(&self) -> bool {
        self.entered
    }

    pub(super) fn take_unreported(&mut self) -> bool {
        std::mem::take(&mut self.unreported)
    }

    pub(super) fn failed(&self) -> bool {
        self.stage.is_some()
            || self.sources.iter().any(Option::is_some)
            || self.controllers.iter().any(Option::is_some)
    }

    pub(super) fn failure(&self) -> Option<QemuNodeError> {
        self.failed().then(|| QemuNodeError::RamCleanup {
            stage: self.stage.clone(),
            stage_latest: self.stage_latest.clone(),
            sources: self.sources.clone(),
            controllers: self.controllers.clone(),
        })
    }

    pub(super) fn retain_stage(&mut self, first: QemuNodeError) {
        self.entered = true;
        if self.stage.is_none() {
            self.stage = Some(Box::new(first));
            self.unreported = true;
        } else if self.stage.as_deref() != Some(&first)
            && self.stage_latest.as_deref() != Some(&first)
        {
            self.stage_latest = Some(Box::new(first));
            self.unreported = true;
        }
    }

    pub(super) fn source(
        &mut self,
        index: usize,
        source: &mut Option<QemuRamSourceService>,
        original: Option<crate::ram_control::RamCleanupOriginal<'_>>,
    ) -> bool {
        self.entered = true;
        let Some(service) = source.as_mut() else {
            return true;
        };
        let (joined, status) = service.stop(original);
        if let Err(first) = status {
            if self.sources[index].as_ref() != Some(&first) {
                self.sources[index] = Some(first);
                self.unreported = true;
            }
            // Deliver this actual negative while the same body remains owned.
            // stop's saved version allows a later factual close without rejoin.
            return false;
        }
        if joined {
            // Only this actual known body return consumes the canonical slot.
            drop(source.take());
        }
        joined
    }

    pub(super) fn controller(
        &mut self,
        index: usize,
        status: Result<(), RamControlRetirementHistory>,
    ) {
        self.entered = true;
        if let Err(first) = status {
            if self.controllers[index].as_ref() != Some(&first) {
                self.controllers[index] = Some(first);
                self.unreported = true;
            }
        }
    }
}
