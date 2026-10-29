//! Actual addressed DO transactions for compact observation slots and receipts.

use anyhow::{ensure, Result};
use rand::TryRngCore as _;
use worker::{Method, Request as HttpRequest, Response, Storage};

use super::super::{
    config::configured,
    protocol::{digest, GUARD_HEADER, SCOPE_HEADER},
    stage,
    state::Head,
    storage::{
        decode, error, key, load_head, transaction_string, ExternalObjectGuard, BINDING, HEAD,
    },
};
use super::{
    protocol::{self, Operation, Receipt, Reply, Request, MAX_MESSAGE, MAX_RECEIPT},
    state,
};

impl ExternalObjectGuard {
    /// Handles bounded authenticated compact read-slot control.
    ///
    /// # Errors
    /// Returns a generic refusal for invalid control or journal failure.
    pub(crate) async fn observation_fetch(
        &self,
        request: &mut HttpRequest,
    ) -> worker::Result<Response> {
        match self.observation_handle(request).await {
            Ok(reply) => {
                let encoded = serde_json::to_string(&reply).map_err(error)?;
                if encoded.len() > MAX_MESSAGE {
                    return Response::error("observation turn refused", 409);
                }
                let headers = worker::Headers::new();
                headers.set("content-type", "application/json")?;
                headers.set("cache-control", "private, no-store")?;
                Ok(Response::ok(encoded)?.with_headers(headers))
            }
            Err(_) => Response::error("observation turn refused", 409),
        }
    }

    async fn observation_handle(&self, request: &mut HttpRequest) -> Result<Reply> {
        ensure!(
            request.method() == Method::Post,
            "invalid observation turn method"
        );
        let bytes = crate::hybrid::read_bounded_body(request, MAX_MESSAGE)
            .await?
            .ok_or_else(|| anyhow::anyhow!("oversized observation turn"))?;
        let signature = request
            .headers()
            .get(GUARD_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("observation signature missing"))?;
        key(&self.env)?.verify_body(&signature, &bytes)?;
        let message: Request = serde_json::from_slice(&bytes)?;
        ensure!(
            message.domain == protocol::DOMAIN && serde_json::to_vec(&message)? == bytes,
            "invalid observation turn encoding"
        );
        let config = configured(&self.env)?.ok_or_else(|| anyhow::anyhow!("consumer disabled"))?;
        let name = message.scope.guard_name()?;
        ensure!(
            message.scope.guard_namespace_id == config.guard_namespace_id
                && request.headers().get(SCOPE_HEADER)?.as_deref() == Some(name.as_str())
                && self
                    .env
                    .durable_object(BINDING)?
                    .id_from_name(&name)?
                    .to_string()
                    == self.state.id().to_string(),
            "observation addressed to another guard"
        );

        let _gate = self.gate.lock().await;
        let storage = self.state.storage();
        let prior = load_head(&storage)
            .await?
            .ok_or_else(|| anyhow::anyhow!("untracked object cannot be observed"))?;
        prior.validate(&config, &message.scope)?;
        match message.operation {
            Operation::Begin { intent, lease } => {
                crate::direct_guard::deny_legacy(&storage).await?;
                intent.validate()?;
                ensure!(
                    intent.object.scope == message.scope,
                    "observation scope differs"
                );
                if let Some(receipt) = load_receipt(&storage, &intent.object.operation_id).await? {
                    ensure!(
                        receipt.turn.intent == intent,
                        "historical observation context differs"
                    );
                    return Ok(Reply::Historical { receipt });
                }
                stage::verify_observable_destination(&self.env, &storage, &prior, &config).await?;
                let mut nonce = [0_u8; 32];
                rand::rngs::OsRng
                    .try_fill_bytes(&mut nonce)
                    .map_err(|_| anyhow::anyhow!("observation randomness unavailable"))?;
                let (next, turn) = state::begin(
                    &prior,
                    &config,
                    intent.clone(),
                    lease.as_bytes(),
                    hex::encode(nonce),
                    config.clock(),
                )?;
                commit(
                    &storage,
                    prior,
                    next.clone(),
                    &intent.object.operation_id,
                    None,
                    None,
                )
                .await?;
                Ok(Reply::Dispatch {
                    turn,
                    floor: next.floor,
                })
            }
            Operation::Terminal { receipt } => {
                receipt.validate()?;
                ensure!(
                    receipt.turn.intent.object.scope == message.scope,
                    "terminal scope differs"
                );
                let operation = receipt.turn.intent.object.operation_id.clone();
                let existing = load_receipt(&storage, &operation).await?;
                if let Some(old) = existing {
                    ensure!(old == receipt, "observation receipt changed");
                    return Ok(Reply::TerminalAcknowledged { receipt });
                }
                let next = state::terminal(&prior, &receipt)?;
                commit(
                    &storage,
                    prior,
                    next,
                    &operation,
                    None,
                    Some(receipt.clone()),
                )
                .await?;
                Ok(Reply::TerminalAcknowledged { receipt })
            }
        }
    }
}

fn receipt_key(operation: &str) -> Result<String> {
    Ok(format!(
        "external-object/observation-receipt/v1/{}",
        digest(&operation)?
    ))
}

async fn load_receipt(storage: &Storage, operation: &str) -> Result<Option<Receipt>> {
    let raw = storage.get::<String>(&receipt_key(operation)?).await?;
    let receipt: Option<Receipt> = decode(raw, MAX_RECEIPT)?;
    if let Some(value) = &receipt {
        value.validate()?;
    }
    Ok(receipt)
}

async fn commit(
    storage: &Storage,
    expected: Head,
    next: Head,
    operation: &str,
    expected_receipt: Option<Receipt>,
    new_receipt: Option<Receipt>,
) -> Result<()> {
    let receipt_key = receipt_key(operation)?;
    let encoded = serde_json::to_string(&next)?;
    ensure!(
        encoded.len() <= super::super::protocol::MAX_MESSAGE,
        "observation head exceeds bound"
    );
    storage
        .transaction(move |transaction| {
            let expected = expected.clone();
            let encoded = encoded.clone();
            let receipt_key = receipt_key.clone();
            let expected_receipt = expected_receipt.clone();
            let new_receipt = new_receipt.clone();
            async move {
                let head: Option<Head> = decode(
                    transaction_string(&transaction, HEAD).await?,
                    super::super::protocol::MAX_MESSAGE,
                )
                .map_err(error)?;
                let current: Option<Receipt> = decode(
                    transaction_string(&transaction, &receipt_key).await?,
                    MAX_RECEIPT,
                )
                .map_err(error)?;
                if head.as_ref() != Some(&expected) || current != expected_receipt {
                    return Err(error("observation CAS refused"));
                }
                if let Some(receipt) = new_receipt {
                    transaction
                        .put(
                            &receipt_key,
                            serde_json::to_string(&receipt).map_err(error)?,
                        )
                        .await?;
                }
                transaction.put(HEAD, encoded).await?;
                Ok(())
            }
        })
        .await?;
    Ok(())
}
