//! Independent authenticated request and native-publication retirement.

use std::collections::BTreeMap;

use crucible_node_contract::*;
use serde_json::{Map, Value};

use crate::ProviderError;
use crate::blob::{BlobCustody, BlobCustodyVerifier, BlobRetirement, TransferKey};
use crate::bodies::{RetireRequest, RetireResult, RetirementDisposition};
use crate::envelope::RequestOrigin;
use crate::journal::{ConsumptionVerifier, RequestKey};
use crate::native_journal::{NativeJournal, NativeRequestPermit};

use super::completed;
use super::resources::{PublicationConsumption, RequestConsumption, Resources};
use super::security::NativeVerifier;

pub(super) fn retire(
    journal: &mut NativeJournal<Resources>,
    permit: &NativeRequestPermit,
    request: &RetireRequest,
    verifier: &NativeVerifier,
) -> Result<Map<String, Value>, ProviderError> {
    if request.disposition == RetirementDisposition::AbandonedInertTransfer {
        return abandon(journal, permit, request);
    }
    let receipt = request
        .custody_receipt
        .0
        .as_ref()
        .ok_or(ProviderError::Correlation(
            "native consumption receipt missing",
        ))?;
    let mut proofs = BTreeMap::new();
    if !request.operation_ids.is_empty() {
        let consumption: PublicationConsumption = journal.resources().resolve(receipt)?;
        if request.operation_ids != [consumption.operation_id.clone()] {
            return Err(ProviderError::Correlation(
                "publication receipt cannot consume another original operation",
            ));
        }
        let original = journal
            .snapshot()
            .operations
            .get(&consumption.operation_id)
            .ok_or(ProviderError::Correlation(
                "original native operation unavailable",
            ))?;
        if !original.domains_released
            || original.outcome.is_none()
            || original.retired
            || request
                .request_ids
                .iter()
                .any(|id| id != &original.request_key.id)
        {
            return Err(ProviderError::Conflict(
                "publication consumption cannot retire unrelated requests",
            ));
        }
        for id in &request.request_ids {
            let key = RequestKey {
                origin: RequestOrigin::Controller,
                id: id.clone(),
            };
            let retained = journal
                .snapshot()
                .requests
                .get(&key)
                .ok_or(ProviderError::Correlation("original request missing"))?;
            let bytes = retained
                .outcome()
                .ok_or(ProviderError::Conflict("request outcome unresolved"))?
                .to_vec();
            proofs.insert(key, (retained.request_hash().clone(), bytes));
        }
        // Authenticated byte transfer and actual child publication ACK establish
        // semantic release; syntactic receipt scope alone never opens the window.
        journal.with_request_resources(permit, |resources| {
            resources.acknowledge_consumption(receipt)
        })?;
        journal.retire_operation(&consumption.operation_id, receipt, verifier)?;
    } else {
        let consumption: RequestConsumption = journal.resources().resolve(receipt)?;
        if consumption.session_id != journal.snapshot().session_id
            || consumption.incarnation_id != journal.snapshot().incarnation_id
            || consumption
                .requests
                .iter()
                .map(|value| value.request_id.clone())
                .collect::<Vec<_>>()
                != request.request_ids
        {
            return Err(ProviderError::Correlation(
                "request custody receipt names foreign original outcomes",
            ));
        }
        for consumed in consumption.requests {
            let key = RequestKey {
                origin: RequestOrigin::Controller,
                id: consumed.request_id,
            };
            let retained = journal
                .snapshot()
                .requests
                .get(&key)
                .ok_or(ProviderError::Correlation("original request missing"))?;
            let bytes = retained.outcome().ok_or(ProviderError::Conflict(
                "original outcome remains unresolved",
            ))?;
            if retained.request_hash() != &consumed.request_hash {
                return Err(ProviderError::Conflict(
                    "consumption changed original request",
                ));
            }
            consumed.outcome.verify(bytes)?;
            proofs.insert(key, (retained.request_hash().clone(), bytes.to_vec()));
        }
    }
    let custody = AuthenticatedConsumption {
        receipt: receipt.clone(),
        proofs,
    };
    for request in &request.request_ids {
        journal.retire_request(RequestOrigin::Controller, request, receipt, &custody)?;
    }
    completed(RetireResult {
        retired_request_ids: request.request_ids.clone(),
        retired_operation_ids: request.operation_ids.clone(),
    })
}

fn abandon(
    journal: &mut NativeJournal<Resources>,
    permit: &NativeRequestPermit,
    request: &RetireRequest,
) -> Result<Map<String, Value>, ProviderError> {
    let mut proofs = BTreeMap::new();
    let mut transfers = std::collections::BTreeSet::new();
    for id in &request.request_ids {
        let original = journal.request_material(RequestOrigin::Controller, id)?;
        let body = crate::bodies::decode_request(original.method, &original.body)?;
        let transfer = match body {
            crate::bodies::RequestBody::BlobBegin(value) => value.transfer_id,
            crate::bodies::RequestBody::BlobChunk(value) => value.transfer_id,
            _ => {
                return Err(ProviderError::Conflict(
                    "only unexposed inert transfers may be abandoned",
                ));
            }
        };
        transfers.insert(TransferKey {
            origin: RequestOrigin::Controller,
            session: journal.snapshot().session_id.clone(),
            incarnation: journal.snapshot().incarnation_id.clone(),
            transfer,
        });
        let key = RequestKey {
            origin: RequestOrigin::Controller,
            id: id.clone(),
        };
        let retained = journal
            .snapshot()
            .requests
            .get(&key)
            .ok_or(ProviderError::Correlation("inert request custody missing"))?;
        proofs.insert(
            key,
            (
                retained.request_hash().clone(),
                retained
                    .outcome()
                    .ok_or(ProviderError::Conflict("inert request outcome unresolved"))?
                    .to_vec(),
            ),
        );
    }
    let receipt = journal.with_request_resources(permit,|resources| {
        for transfer in &transfers {
            resources.blobs.retire(RequestOrigin::Controller,transfer,BlobRetirement::AbandonInert,&InertOnly)?;
        }
        resources.store_json(serde_json::json!({"schema":"reference-device/inert-abandonment-v1",
            "session_id":resources.bootstrap.authority.session_id,"incarnation_id":resources.bootstrap.authority.incarnation_id,
            "request_ids":request.request_ids,"transfer_ids":transfers.iter().map(|key|&key.transfer).collect::<Vec<_>>(),
            "native_disposition":"unexposed-inert-transfer-abandoned"}))
    })?;
    let custody = AuthenticatedConsumption {
        receipt: receipt.clone(),
        proofs,
    };
    for id in &request.request_ids {
        journal.retire_request(RequestOrigin::Controller, id, &receipt, &custody)?;
    }
    completed(RetireResult {
        retired_request_ids: request.request_ids.clone(),
        retired_operation_ids: Vec::new(),
    })
}

struct InertOnly;

impl BlobCustodyVerifier for InertOnly {
    fn verify_custody(
        &self,
        _: &TransferKey,
        _: &ContentRef,
        _: &BlobCustody,
        _: &ContentRef,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "inert abandonment cannot manufacture semantic custody",
        ))
    }
}

// Constructed after installed native evidence and actual controller channel
// authentication above; no public constructor or deserializer mints this proof.
struct AuthenticatedConsumption {
    receipt: ContentRef,
    proofs: BTreeMap<RequestKey, (HashRef, Vec<u8>)>,
}

impl ConsumptionVerifier for AuthenticatedConsumption {
    fn verify(
        &self,
        key: &RequestKey,
        hash: &HashRef,
        bytes: &[u8],
        receipt: &ContentRef,
    ) -> Result<(), ProviderError> {
        if receipt != &self.receipt
            || !self
                .proofs
                .get(key)
                .is_some_and(|(original_hash, original_bytes)| {
                    original_hash == hash && original_bytes == bytes
                })
        {
            return Err(ProviderError::Correlation(
                "authentic original outcome custody differs",
            ));
        }
        Ok(())
    }
}
