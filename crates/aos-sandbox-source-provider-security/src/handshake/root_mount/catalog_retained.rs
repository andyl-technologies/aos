//! Retains the complete original catalog answer through authentication.
//!
//! Only this child moves an independently checked Bound packet into a catalog
//! proof. Pending or failed exchanges keep their exact nonce and packet.

use super::*;
use crate::handshake::mount_request::OriginalBoundaryV5;

impl CurrentRootMountSourceProviderSessionV1 {
    pub(in crate::handshake) fn fail_original_catalog_v5(&mut self) {
        if let Some(exchange) = &mut self.catalog_exchange {
            exchange.failed = true;
        }
    }

    pub(in crate::handshake) fn advance_catalog_currentness_retaining_v5(
        &mut self,
        minimum: &ProviderCatalogFloorV1,
        mut require_current: impl FnMut() -> Result<(), SourceProviderSecurityError>,
        proof_slot: &mut Option<AuthenticatedRootMountCatalogCurrentnessV1>,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, ()).run(|owner, _| {
            if proof_slot.is_some() {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            owner.revalidate()?;
            require_current().map_err(|error| owner.poison(error))?;
            if owner.recovery_exchange.is_some()
                || owner.inventory_readback_exchange.is_some()
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let inner = owner.custody.inner();
            if minimum.provider_authority_id()
                != inner.provider_authority().authority().authority_id()
                || minimum.resource_namespace_digest()
                    != inner.route().resource_namespace_digest()
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let requested = (
                minimum.minimum_catalog_generation(),
                minimum.minimum_catalog_digest(),
            );
            if owner.catalog_floor.is_some_and(|previous| {
                requested.0 < previous.0
                    || (requested.0 == previous.0 && requested.1 != previous.1)
            }) {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }

            if let Some(exchange) = &owner.catalog_exchange {
                if exchange.failed || exchange.query.minimum() != requested {
                    return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
                }
            } else {
                let now = current_unix_seconds()?;
                let nonce = owner.custody.draw_nonce_at(now)?;
                let sequence = owner.catalog_sequence.checked_add(1).ok_or_else(|| {
                    owner.poison(SourceProviderSecurityError::SessionContinuity)
                })?;
                let query = CatalogCurrentnessQueryV1::new(
                    owner.session.binding(),
                    nonce,
                    sequence,
                    requested.0,
                    requested.1,
                )
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
                owner.catalog_exchange = Some(RootCatalogExchangeV1 {
                    query,
                    sent: false,
                    received: None,
                    signed: None,
                    failed: false,
                });
            }

            require_current().map_err(|error| owner.poison(error))?;
            let exchange = owner.catalog_exchange.as_mut()
                .ok_or(SourceProviderSecurityError::Poisoned)?;
            if !exchange.sent {
                match owner.carrier.send(&exchange.query.to_canonical_bytes()) {
                    Ok(()) => exchange.sent = true,
                    Err(CarrierFailureV1::Retryable) => return Ok(false),
                    Err(CarrierFailureV1::Fatal(error)) => return Err(owner.poison(error)),
                }
            }
            require_current().map_err(|error| owner.poison(error))?;
            match owner.carrier.receive_zero_descriptors_retaining_v5(
                aos_sandbox_source_provider_protocol::MAXIMUM_FRAME_BYTES,
                &mut exchange.received,
            ) {
                Ok(true) => {}
                Ok(false) | Err(CarrierFailureV1::Retryable) => return Ok(false),
                Err(CarrierFailureV1::Fatal(error)) => return Err(owner.poison(error)),
            }
            let received = exchange.received.as_ref()
                .and_then(RetainedSourceProviderRecordV5::bound)
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if !received.descriptors.is_empty()
                || !received.execution.has_same_execution(&owner.provider_execution)
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            exchange.signed = Some(
                SignedCatalogCurrentnessV1::from_canonical_bytes(&received.payload)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
            );

            owner.revalidate()?;
            require_current().map_err(|error| owner.poison(error))?;
            let (signer, trusted_key) = {
                let inner = owner.custody.inner();
                let signer = inner.provider_authority().traffic_signer().clone();
                let trusted_key = inner.trust().keys().iter()
                    .find(|entry| {
                        entry.signer() == &signer
                            && entry.state() == SourceProviderKeyTrustStateV1::Eligible
                    })
                    .map(|entry| *entry.public_key());
                (signer, trusted_key)
            };
            let trusted_key = trusted_key.ok_or_else(|| {
                owner.poison(SourceProviderSecurityError::SessionContinuity)
            })?;
            let exchange = owner.catalog_exchange.as_ref()
                .ok_or(SourceProviderSecurityError::Poisoned)?;
            let signed = exchange.signed.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            signed.verify_for_query(&exchange.query, &signer, &trusted_key)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            let sequence = exchange.query.sequence();
            let floor = signed.floor();
            let cookie = owner.carrier.socket().peer().socket_cookie();

            // This helper performs only moves. Failed structural handoff returns
            // the whole exchange rather than dropping any actual received owner.
            let exchange = owner.catalog_exchange.take();
            match park_verified_catalog(exchange, cookie, proof_slot) {
                Ok(()) => {
                    owner.catalog_sequence = sequence;
                    owner.catalog_floor = Some(floor);
                    Ok(true)
                }
                Err(exchange) => {
                    owner.catalog_exchange = exchange;
                    Err(owner.poison(SourceProviderSecurityError::SessionContinuity))
                }
            }
        })
    }
}

fn park_verified_catalog(
    exchange: Option<RootCatalogExchangeV1>,
    socket_cookie: NonZeroU64,
    proof_slot: &mut Option<AuthenticatedRootMountCatalogCurrentnessV1>,
) -> Result<(), Option<RootCatalogExchangeV1>> {
    let Some(RootCatalogExchangeV1 {
        query,
        sent,
        received,
        signed,
        failed,
    }) = exchange else {
        return Err(None);
    };
    match (received, signed) {
        (Some(RetainedSourceProviderRecordV5::Bound(received)), Some(signed)) => {
            *proof_slot = Some(AuthenticatedRootMountCatalogCurrentnessV1 {
                signed,
                query,
                socket_cookie,
                received,
            });
            Ok(())
        }
        (received, signed) => Err(Some(RootCatalogExchangeV1 {
            query,
            sent,
            received,
            signed,
            failed,
        })),
    }
}
