//! Sole-writer receiving journal cuts under the live maintenance original.

use super::*;
use crate::assignment_ledger::{ReceivingTransferCas, ReceivingTransferRecord};
use crucible_host_resources::host_supervision::HostSupervisionError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReceivingTransitionFailure {
    #[error("receiving transfer original refused")]
    Original(#[source] HostSupervisionError),
    #[error("receiving transfer journal lookup failed")]
    Ledger(#[source] crate::AssignmentLedgerError),
    #[error("receiving transfer journal binding conflicts")]
    Conflict,
    #[error("receiving transfer persistence failed; acceptance remains withheld")]
    Persistence {
        #[source]
        source: crate::AssignmentLedgerError,
        observed: bool,
        reconciliation: Option<crate::AssignmentLedgerError>,
        original: Option<HostSupervisionError>,
    },
}

impl<V: AttemptAdmissionValidator> LocalExecutorSupervisor<crate::DirectoryAssignmentLedger, V> {
    pub(crate) fn write_receiving_transfer(
        &mut self,
        expected: Option<ReceivingTransferRecord>,
        next: ReceivingTransferRecord,
        boundary: &mut dyn FnMut() -> Result<(), HostSupervisionError>,
    ) -> Result<(), ReceivingTransitionFailure> {
        boundary().map_err(ReceivingTransitionFailure::Original)?;
        let current = self
            .ledger
            .load_receiving_transfer(next)
            .map_err(ReceivingTransitionFailure::Ledger)?;
        // A recovered Ready observation cannot reissue the live claim. Exact
        // terminal repetition is only usable by the already-retained owner.
        if expected.is_some() && current == Some(next) {
            return boundary().map_err(ReceivingTransitionFailure::Original);
        }
        if current != expected {
            return Err(ReceivingTransitionFailure::Conflict);
        }
        boundary().map_err(ReceivingTransitionFailure::Original)?;
        match self
            .ledger
            .compare_exchange_receiving_transfer(expected, next)
        {
            Ok(ReceivingTransferCas::Advanced) => {
                boundary().map_err(ReceivingTransitionFailure::Original)
            }
            Ok(ReceivingTransferCas::Conflict) => Err(ReceivingTransitionFailure::Conflict),
            Err(source) => {
                if let Err(original) = boundary() {
                    return Err(ReceivingTransitionFailure::Persistence {
                        source,
                        observed: false,
                        reconciliation: None,
                        original: Some(original),
                    });
                }
                let (observed, reconciliation) = match self.ledger.load_receiving_transfer(next) {
                    Ok(current) => (current == Some(next), None),
                    Err(error) => (false, Some(error)),
                };
                Err(ReceivingTransitionFailure::Persistence {
                    source,
                    observed,
                    reconciliation,
                    original: boundary().err(),
                })
            }
        }
    }
}
