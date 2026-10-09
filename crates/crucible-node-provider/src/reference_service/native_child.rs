//! Preserves legacy native calls while separately owning selected lineage windows.

use std::{path::Path, time::Duration};

use crucible_node_contract::{ContentRef, Id, InputBatch, U64, canonical};

use crate::{
    ProviderError,
    reference_device::{DeviceGrant, DeviceReceipt, DeviceStatus, ReferenceDevice},
    reference_lineage::{
        ConsumptionRelationCredit, LineageCustodyQueue, LineageDeviceStatus, LineageStage,
        NativeConsumptionRelation, NativeLineageDevice,
    },
};

pub(super) enum ReferenceChild {
    Legacy(Box<ReferenceDevice>),
    Lineage(Box<LineagePeer>),
}

pub(super) struct LineagePeer {
    native: NativeLineageDevice,
    pid: u32,
    timeout: Duration,
    accepted: Vec<AcceptedWindow>,
}

struct AcceptedWindow {
    stage: LineageStage,
    input: Vec<u8>,
    credit: Option<ConsumptionRelationCredit>,
    relation: Option<NativeConsumptionRelation>,
    closed: Option<DeviceReceipt>,
}

impl ReferenceChild {
    pub(super) fn spawn(
        executable: &Path,
        parent: &Path,
        owner: Id,
        incarnation: Id,
        generation: U64,
        timeout: Duration,
        lineage: bool,
    ) -> Result<Self, ProviderError> {
        if !lineage {
            return ReferenceDevice::spawn(
                executable,
                parent,
                owner,
                incarnation,
                generation,
                timeout,
            )
            .map(|native| Self::Legacy(Box::new(native)));
        }
        let mut accepted = Vec::new();
        accepted.try_reserve_exact(64).map_err(|_| {
            ProviderError::ResourceExhausted("lineage accepted source window slots")
        })?;
        let queue = LineageCustodyQueue::new()?;
        let native = NativeLineageDevice::spawn(
            executable,
            parent,
            owner,
            incarnation,
            generation,
            timeout,
            queue,
        )?;
        let pid = native.origin()?.child_pid();
        Ok(Self::Lineage(Box::new(LineagePeer {
            native,
            pid,
            timeout,
            accepted,
        })))
    }

    pub(super) fn origin(
        &self,
    ) -> Result<Option<crate::reference_lineage::NativeLineageOrigin<'_>>, ProviderError> {
        match self {
            Self::Legacy(_) => Ok(None),
            Self::Lineage(peer) => peer.native.origin().map(Some),
        }
    }

    pub(super) fn child_pid(&self) -> u32 {
        match self {
            Self::Legacy(native) => native.child_pid(),
            Self::Lineage(peer) => peer.pid,
        }
    }

    pub(super) fn status(&self) -> DeviceStatus {
        match self {
            Self::Legacy(native) => native.status(),
            Self::Lineage(peer) => match peer.native.status() {
                LineageDeviceStatus::Parked => DeviceStatus::Parked,
                LineageDeviceStatus::Staged => DeviceStatus::Staged,
                LineageDeviceStatus::Active => DeviceStatus::Active,
                LineageDeviceStatus::ClosedPending => DeviceStatus::ClosedPending,
                LineageDeviceStatus::Quarantined => DeviceStatus::Quarantined,
                LineageDeviceStatus::Reclaimed => DeviceStatus::Reaped,
            },
        }
    }

    pub(super) fn stage(
        &mut self,
        grant: DeviceGrant,
        original: &InputBatch,
        input: &[u8],
    ) -> Result<(), ProviderError> {
        let Self::Lineage(peer) = self else {
            let Self::Legacy(native) = self else {
                return Err(ProviderError::Correlation(
                    "native child selection unavailable",
                ));
            };
            return native.stage(grant, input);
        };
        if original.events.len() > 64 || input.len() > 4096 {
            return Err(ProviderError::ResourceExhausted(
                "lineage source input geometry",
            ));
        }
        let raw = canonical::canonical_json(
            &serde_json::to_value(original).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(original.events.len())
            .map_err(|_| ProviderError::ResourceExhausted("lineage source payload index"))?;
        let mut start = 0_usize;
        for event in &original.events {
            let length = usize::try_from(event.payload.length.get())
                .map_err(|_| ProviderError::ResourceExhausted("lineage payload length"))?;
            let end = start
                .checked_add(length)
                .ok_or(ProviderError::ResourceExhausted(
                    "lineage payload arithmetic",
                ))?;
            payloads.push(input.get(start..end).ok_or(ProviderError::Correlation(
                "accepted source payload extent changed",
            ))?);
            start = end;
        }
        if start != input.len() {
            return Err(ProviderError::Correlation(
                "accepted source input has unscoped bytes",
            ));
        }
        let stage = LineageStage::from_input_batch(
            grant,
            canonical::content_ref(&raw, "application/json")?,
            &raw,
            &payloads,
        )?;
        if let Some(original) = peer
            .accepted
            .iter()
            .find(|window| window.stage.grant.window_id == stage.grant.window_id)
        {
            return if original.stage == stage && original.input == raw {
                Ok(())
            } else {
                Err(ProviderError::Conflict(
                    "lineage original source stage changed",
                ))
            };
        }
        if peer.accepted.len() >= 64 || peer.native.status() != LineageDeviceStatus::Parked {
            return Err(ProviderError::ResourceExhausted(
                "lineage source window custody unavailable",
            ));
        }
        let credit = ConsumptionRelationCredit::reserve(&stage, &raw)?;
        peer.accepted.push(AcceptedWindow {
            stage: stage.clone(),
            input: raw,
            credit: Some(credit),
            relation: None,
            closed: None,
        });
        // Accepted source input and all copy credits survive a failed native
        // Stage. The enclosing original NativeJournal then remains Unknown.
        peer.native.stage(stage)
    }

    pub(super) fn activate(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        match self {
            Self::Legacy(native) => native.activate(grant),
            Self::Lineage(peer) => {
                peer.check_current(grant)?;
                peer.native.activate().map(|_| ())
            }
        }
    }

    pub(super) fn close(&mut self, grant: &DeviceGrant) -> Result<DeviceReceipt, ProviderError> {
        let Self::Lineage(peer) = self else {
            let Self::Legacy(native) = self else {
                return Err(ProviderError::Correlation(
                    "native child selection unavailable",
                ));
            };
            return native.close(grant);
        };
        peer.check_current(grant)?;
        let closed = peer.native.close()?;
        let current = peer.accepted.last_mut().ok_or(ProviderError::Correlation(
            "lineage original source stage unavailable",
        ))?;
        if let Some(receipt) = &current.closed {
            return Ok(receipt.clone());
        }
        let native = peer.native.associate_consumption(&closed, &current.input)?;
        let measured_host_ns =
            native
                .window()
                .measured_host_ns()
                .ok_or(ProviderError::Correlation(
                    "lineage original physical duration unavailable",
                ))?;
        let credit = current.credit.take().ok_or(ProviderError::Correlation(
            "lineage relation copying already failed; original source remains held",
        ))?;
        let relation = NativeConsumptionRelation::collect(&native, credit)?;
        let receipt = DeviceReceipt {
            grant: closed.grant,
            output: closed.output,
            measured_host_ns,
            application_parked: closed.application_parked,
        };
        current.relation = Some(relation);
        current.closed = Some(receipt.clone());
        Ok(receipt)
    }

    pub(super) fn validate_receipt(&self, receipt: &DeviceReceipt) -> Result<(), ProviderError> {
        match self {
            Self::Legacy(native) => native.validate_receipt(receipt),
            Self::Lineage(peer) => {
                let original = peer
                    .accepted
                    .iter()
                    .find(|window| window.closed.as_ref() == Some(receipt))
                    .ok_or(ProviderError::Correlation(
                        "lineage source receipt lacks original custody",
                    ))?;
                let actual = peer
                    .native
                    .windows()
                    .iter()
                    .find_map(|window| {
                        window
                            .closure()
                            .filter(|closed| closed.grant == receipt.grant)
                    })
                    .ok_or(ProviderError::Correlation(
                        "lineage actual native closure unavailable",
                    ))?;
                peer.native.validate_closure(actual)?;
                if original.relation.is_none() || actual.output != receipt.output {
                    return Err(ProviderError::Correlation(
                        "lineage original consumption differs",
                    ));
                }
                Ok(())
            }
        }
    }

    pub(super) fn relation(
        &self,
        grant: &DeviceGrant,
    ) -> Result<Option<&NativeConsumptionRelation>, ProviderError> {
        match self {
            Self::Legacy(_) => Ok(None),
            Self::Lineage(peer) => peer
                .accepted
                .iter()
                .find(|window| &window.stage.grant == grant)
                .and_then(|window| window.relation.as_ref())
                .map(Some)
                .ok_or(ProviderError::Correlation(
                    "lineage original relation unavailable",
                )),
        }
    }

    pub(super) fn evidence(
        &self,
        reference: &ContentRef,
    ) -> Option<&crate::reference_lineage::ConsumptionEvidence> {
        let Self::Lineage(peer) = self else {
            return None;
        };
        peer.accepted
            .iter()
            .filter_map(|window| window.relation.as_ref())
            .flat_map(NativeConsumptionRelation::evidence)
            .find(|object| object.reference() == reference)
    }

    pub(super) fn acknowledge_publication(
        &mut self,
        grant: &DeviceGrant,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Legacy(native) => native.acknowledge_publication(grant),
            Self::Lineage(peer) => {
                let receipt = peer
                    .native
                    .windows()
                    .iter()
                    .find_map(|window| window.closure().filter(|closed| &closed.grant == grant))
                    .cloned()
                    .ok_or(ProviderError::Correlation(
                        "lineage original public ACK has no native closure",
                    ))?;
                peer.native.acknowledge_publication(&receipt)
            }
        }
    }

    pub(super) fn quarantine(&mut self) -> Result<bool, ProviderError> {
        match self {
            Self::Legacy(native) => native.quarantine(),
            Self::Lineage(peer) => {
                super::native_supervision::quarantine(&mut peer.native, peer.timeout)
            }
        }
    }
}

impl LineagePeer {
    fn check_current(&self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        if self
            .accepted
            .last()
            .is_none_or(|window| &window.stage.grant != grant)
        {
            return Err(ProviderError::Correlation(
                "lineage command changed original source grant",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "native_child_tests.rs"]
mod tests;
