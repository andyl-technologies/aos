//! Keeps pre-thread topology custody occupied across every later startup refusal.

use super::{
    AttachBridge, GuestProcessEffectErrorV1, GuestProcessEffectsV1, GuestProcessStartupErrorV1,
    Ledger,
};

impl GuestProcessStartupErrorV1 {
    pub(super) fn open() -> Result<GuestProcessEffectsV1, Box<Self>> {
        let mut original = Box::new(Self {
            topology: Some(Box::new(
                aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1::new(),
            )),
            ledger: None,
            bridge: None,
            cause: None,
        });
        let body = original.capture();
        match body {
            Ok(effects) => Ok(effects),
            Err(cause) => {
                original.cause = Some(Box::new(cause));
                Err(original)
            }
        }
    }

    fn capture(&mut self) -> Result<GuestProcessEffectsV1, GuestProcessEffectErrorV1> {
        self.topology
            .as_mut()
            .ok_or_else(incomplete)?
            .capture_inherited_once_v1()
            .map_err(|_| {
                GuestProcessEffectErrorV1::Unavailable("original pre-thread topology refused")
            })?;
        self.ledger = Some(Ledger::open()?);
        let ledger = self.ledger.as_ref().ok_or_else(incomplete)?;
        let quiesced = ledger.read_quiesced()?;
        self.bridge = Some(AttachBridge::start(ledger.clone())?);

        // Validate every destination before moving any owning field. The
        // native producer alone can expose these same completed fixed roots.
        if self.ledger.is_none() || self.bridge.is_none() || self.topology.is_none() {
            return Err(incomplete());
        }
        let (payload, execution_root) = self
            .topology
            .as_mut()
            .ok_or_else(incomplete)?
            .take_completed_parts_v1()
            .ok_or_else(incomplete)?;
        let Some(ledger) = self.ledger.take() else {
            std::process::abort();
        };
        let Some(bridge) = self.bridge.take() else {
            std::process::abort();
        };
        let Some(topology) = self.topology.take() else {
            std::process::abort();
        };
        Ok(GuestProcessEffectsV1 {
            ledger,
            bridge,
            execution_root,
            _payload_cgroup: payload,
            _runtime_topology: topology,
            gate: None,
            gate_installation: None,
            transport_retirement: None,
            quiesced,
        })
    }

    /// Borrows the original startup source without new native observations.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.topology
            .as_ref()
            .and_then(|original| original.failure())
            .or_else(|| self.cause.as_ref().map(|cause| cause.as_ref() as _))
    }
}

impl std::fmt::Debug for GuestProcessStartupErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestProcessStartupErrorV1")
            .field("topology", &self.topology)
            .field("failure", &self.failure())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for GuestProcessStartupErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => write!(formatter, "{cause}"),
            None => formatter.write_str("original startup remains occupied"),
        }
    }
}

impl std::error::Error for GuestProcessStartupErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

impl GuestProcessStartupErrorV1 {
    /// Reports a failed entered topology that still belongs to its original Guardian.
    ///
    /// This is a negative ownership disposition, with no signal or cleanup authority.
    #[must_use]
    pub fn requires_original_guardian_hold_v1(&self) -> bool {
        self.topology.as_ref().is_some_and(|topology|
            topology.requires_original_guardian_hold_v1())
    }
}

fn incomplete() -> GuestProcessEffectErrorV1 {
    GuestProcessEffectErrorV1::Unavailable("original Guest startup handoff is incomplete")
}
