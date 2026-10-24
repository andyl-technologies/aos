//! Inline ownership of the exact loop returned through the session boundary.

use super::*;

pub(crate) struct OwnedQuantumLoop<L: QuantumLoop> {
    body: Option<L>,
}

impl<L: QuantumLoop> OwnedQuantumLoop<L> {
    pub(crate) fn new(body: L) -> Self {
        Self { body: Some(body) }
    }

    #[cfg(test)]
    pub(crate) fn get(&self) -> Result<&L, SchedulerError> {
        self.body.as_ref().ok_or_else(consumed_loop)
    }

    pub(crate) fn get_mut(&mut self) -> Result<&mut L, SchedulerError> {
        self.body.as_mut().ok_or_else(consumed_loop)
    }

    pub(crate) fn into_inner(mut self) -> Result<L, SchedulerError> {
        self.body.take().ok_or_else(consumed_loop)
    }
}

impl<L: QuantumLoop> Drop for OwnedQuantumLoop<L> {
    fn drop(&mut self) {
        if let Some(body) = self.body.take() {
            body.retire_owned();
        }
    }
}

fn consumed_loop() -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: String::from("the session quantum loop has already been consumed"),
    }
}
