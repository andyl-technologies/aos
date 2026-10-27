//! The fault-command seam between live callbacks and the fault bridge.
//!
//! Callbacks drive fault commands through [`LiveFaultCommandControl`] so unit
//! tests can substitute a bridge that records what each callback pumped,
//! dispatched and drained without mapping a real fault-command region.

use super::*;

pub(in crate::runtime) trait LiveFaultCommandControl {
    fn initialize(&mut self) -> Result<(), crate::fault_command::FaultCommandBridgeError>;

    fn pump(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError>;

    fn pump_with_offset_reader(
        &mut self,
        raw_icount: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        self.pump(offset_reader()?, raw_icount)
    }

    fn pump_through_frontier(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
        frontier: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError>;

    fn pump_through_frontier_with_offset_reader(
        &mut self,
        raw_icount: u64,
        frontier: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        self.pump_through_frontier(offset_reader()?, raw_icount, frontier)
    }

    fn dispatch_node_boundary(
        &mut self,
        raw_icount: u64,
    ) -> Result<(), crate::fault_command::FaultCommandBridgeError>;

    fn drain_publications(
        &mut self,
        logical_icount_offset: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError>;

    fn command_frontier_is_settled(&self, frontier: u64) -> bool;
}

impl LiveFaultCommandControl for FaultCommandBridge {
    fn initialize(&mut self) -> Result<(), crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::initialize(self)
    }

    fn pump(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::pump(self, logical_icount_offset, raw_icount)
    }

    fn pump_with_offset_reader(
        &mut self,
        raw_icount: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::pump_with_offset_reader(self, raw_icount, offset_reader)
    }

    fn pump_through_frontier(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
        frontier: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::pump_through_frontier(self, logical_icount_offset, raw_icount, frontier)
    }

    fn pump_through_frontier_with_offset_reader(
        &mut self,
        raw_icount: u64,
        frontier: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::pump_through_frontier_with_offset_reader(
            self,
            raw_icount,
            frontier,
            offset_reader,
        )
    }

    fn dispatch_node_boundary(
        &mut self,
        raw_icount: u64,
    ) -> Result<(), crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::dispatch_node_boundary(self, raw_icount)
    }

    fn drain_publications(
        &mut self,
        logical_icount_offset: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::drain_publications(self, logical_icount_offset)
    }

    fn command_frontier_is_settled(&self, frontier: u64) -> bool {
        FaultCommandBridge::command_frontier_is_settled(self, frontier)
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct TestFaultCommandObservation {
    pub(super) pumped_frontier: Option<u64>,
    pub(super) boundary_dispatched: bool,
    pub(super) publications_drained: bool,
}

#[cfg(test)]
pub(in crate::runtime) struct TestFaultCommandBridge {
    observation: Arc<Mutex<TestFaultCommandObservation>>,
    advance_tick_on_pump: Option<i64>,
}

#[cfg(test)]
impl TestFaultCommandBridge {
    pub(super) fn empty() -> Self {
        Self {
            observation: Arc::new(Mutex::new(TestFaultCommandObservation::default())),
            advance_tick_on_pump: None,
        }
    }

    pub(super) fn advancing_to(tick: i64) -> Self {
        Self {
            advance_tick_on_pump: Some(tick),
            ..Self::empty()
        }
    }

    pub(super) fn observed() -> (Self, Arc<Mutex<TestFaultCommandObservation>>) {
        let observation = Arc::new(Mutex::new(TestFaultCommandObservation::default()));
        (
            Self {
                observation: Arc::clone(&observation),
                advance_tick_on_pump: None,
            },
            observation,
        )
    }
}

#[cfg(test)]
impl LiveFaultCommandControl for TestFaultCommandBridge {
    fn initialize(&mut self) -> Result<(), crate::fault_command::FaultCommandBridgeError> {
        Ok(())
    }

    fn pump(
        &mut self,
        _logical_icount_offset: u64,
        _raw_icount: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        Ok(true)
    }

    fn pump_with_offset_reader(
        &mut self,
        _raw_icount: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        offset_reader()?;
        if let Some(tick) = self.advance_tick_on_pump.take() {
            tests::TEST_SIM_TICK.set(tick);
        }
        offset_reader()?;
        Ok(true)
    }

    fn pump_through_frontier(
        &mut self,
        _logical_icount_offset: u64,
        _raw_icount: u64,
        frontier: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        if frontier == 0 {
            self.observation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pumped_frontier = Some(frontier);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn dispatch_node_boundary(
        &mut self,
        _raw_icount: u64,
    ) -> Result<(), crate::fault_command::FaultCommandBridgeError> {
        let mut observation = self
            .observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        observation.boundary_dispatched = observation.pumped_frontier.is_some();
        Ok(())
    }

    fn drain_publications(
        &mut self,
        _logical_icount_offset: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        let mut observation = self
            .observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        observation.publications_drained = observation.boundary_dispatched;
        Ok(observation.publications_drained)
    }

    fn command_frontier_is_settled(&self, frontier: u64) -> bool {
        let observation = self
            .observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        observation.pumped_frontier == Some(frontier)
            && observation.boundary_dispatched
            && observation.publications_drained
    }
}
