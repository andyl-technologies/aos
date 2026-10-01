//! Signed authority admission and its durable physical reservation ledger.
//!
//! This control-only Durable Object uses an operator-configured actual guard
//! namespace identity. It neither dispatches S3 effects nor grants deletion
//! capability. Object bodies and provider secrets never enter its storage.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_hub_core::storage_authority::control::{
    sign_authority_message, verify_authority_message, StorageAuthorityRequest,
    MAX_AUTHORITY_CONTROL_BYTES,
};
use aos_hub_core::storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER};
use futures_util::lock::{Mutex, OwnedMutexGuard};
use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{
    durable_object, DurableObject, Env, Headers, Method, Request, RequestInit, Response, State,
    Storage,
};

use crate::hybrid_authority_state as ledger;

const BINDING: &str = "HYBRID_AUTHORITY_STATE";
const NAMESPACE_VARIABLE: &str = "HUB_EXTERNAL_GUARD_NAMESPACE_ID";
const EXECUTOR_VARIABLE: &str = "HUB_EXTERNAL_STORAGE_EXECUTOR_ID";

/// Permanently reserves approved physical identities and their admission floors.
#[durable_object]
pub struct HybridAuthorityState {
    state: State,
    env: Env,
    gate: Arc<Mutex<()>>,
}

impl DurableObject for HybridAuthorityState {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            gate: Arc::new(Mutex::new(())),
        }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        if request.method() == Method::Post
            && matches!(
                request.url()?.path(),
                "/issuer-reserve" | "/issuer-activate"
            )
        {
            return match self.reserve_issuer(request).await {
                Ok(response) => Ok(response),
                Err(_) => Response::error("issuer registry reservation remains pending", 409),
            };
        }
        if request.method() != Method::Post || request.url()?.path() != "/control" {
            return Response::error("not found", 404);
        }
        let Some((namespace, executor)) = configured_domain(&self.env) else {
            return Response::error("physical authority domain is not configured", 503);
        };
        let namespace_binding = self.env.durable_object(BINDING)?;
        let expected = namespace_binding.id_from_name(LEDGER_NAME)?;
        if expected.to_string() != self.state.id().to_string() {
            return Response::error("authority ledger address differs", 400);
        }
        let Some(signature) = request.headers().get(STORAGE_WORK_SIGNATURE_HEADER)? else {
            return Response::error("authority signature is required", 401);
        };
        let Some(body) =
            crate::hybrid::read_bounded_body(&mut request, MAX_AUTHORITY_CONTROL_BYTES).await?
        else {
            return Response::error("authority body is too large", 413);
        };
        let key = StorageWorkKey::new(self.env.secret("HUB_STORAGE_WORK_KEY")?.to_string())
            .map_err(storage_error)?;
        if verify_authority_message(&key, false, &signature, &body).is_err() {
            return Response::error("authority signature is invalid", 401);
        }
        let Ok(control) = serde_json::from_slice::<StorageAuthorityRequest>(&body) else {
            return Response::error("authority request is invalid", 400);
        };
        let deployment = self.env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let _permit = acquire_gate(Arc::clone(&self.gate)).await;
        let mut journal = DurableAuthorityJournal {
            storage: self.state.storage(),
            chunked: false,
        };
        let reply = match ledger::handle(
            &mut journal,
            &control,
            &deployment,
            &namespace,
            &executor,
            aos_hub_core::clock::now_unix_secs(),
        )
        .await
        {
            Ok(reply) => reply,
            Err(error) => {
                worker::console_error!("hybrid_authority_control_rejected: {error:#}");
                return Response::error("authority control requires reconciliation", 409);
            }
        };
        let bytes = serde_json::to_vec(&reply)?;
        let signature = sign_authority_message(&key, true, &bytes).map_err(storage_error)?;
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        headers.set("cache-control", "private, no-store")?;
        headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
        Ok(Response::from_bytes(bytes)?.with_headers(headers))
    }
}

// Preserve the legacy small-map storage encoding for ordinary authority control.
#[derive(Serialize)]
#[serde(transparent)]
struct StorageBatch(#[serde(with = "serde_wasm_bindgen::preserve")] JsValue);

struct DurableAuthorityJournal {
    storage: Storage,
    chunked: bool,
}

impl ledger::AuthorityJournal for DurableAuthorityJournal {
    async fn get(&mut self, key: &str) -> Result<Option<Value>> {
        let encoded = if self.chunked {
            crate::authority_issuer_storage::read(&self.storage, key).await?
        } else {
            self.storage
                .get::<String>(key)
                .await
                .context("reading versioned authority storage string")?
        };
        encoded
            .map(|encoded| ledger::decode_journal_value(&encoded))
            .transpose()
    }

    async fn put_atomic(&mut self, values: BTreeMap<String, Value>) -> Result<()> {
        let chunked = self.chunked;
        self.storage
            .transaction(move |transaction| async move {
                if chunked {
                    for (key, value) in values {
                        let encoded =
                            ledger::encode_journal_value(&value).map_err(storage_error)?;
                        crate::authority_issuer_storage::write(&transaction, &key, &encoded)
                            .await?;
                    }
                } else {
                    for batch in ledger::write_batches(values) {
                        let encoded = batch
                            .into_iter()
                            .map(|(key, value)| {
                                ledger::encode_journal_value(&value)
                                    .map(|value| (key, value))
                                    .map_err(storage_error)
                            })
                            .collect::<worker::Result<BTreeMap<_, _>>>()?;
                        let values =
                            encoded.serialize(&serde_wasm_bindgen::Serializer::json_compatible())?;
                        transaction.put_multiple(StorageBatch(values)).await?;
                    }
                }
                Ok(())
            })
            .await
            .context("persisting authority reservations, head and receipt")
    }
}

/// Forwards exact signed bytes to the configured control-plane DO.
///
/// # Errors
/// Returns an error when configured DO storage is unavailable. Missing physical
/// domain configuration rejects control without affecting ordinary R2 routes.
pub(crate) async fn control(mut request: Request, env: &Env) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return Response::error("method not allowed", 405);
    }
    let Some((namespace, _)) = configured_domain(env) else {
        return Response::error("physical authority domain is not configured", 503);
    };
    let Some(signature) = request.headers().get(STORAGE_WORK_SIGNATURE_HEADER)? else {
        return Response::error("authority signature is required", 401);
    };
    let Some(body) =
        crate::hybrid::read_bounded_body(&mut request, MAX_AUTHORITY_CONTROL_BYTES).await?
    else {
        return Response::error("authority body is too large", 413);
    };
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())
        .map_err(storage_error)?;
    if verify_authority_message(&key, false, &signature, &body).is_err() {
        return Response::error("authority signature is invalid", 401);
    }
    let Ok(control) = serde_json::from_slice::<StorageAuthorityRequest>(&body) else {
        return Response::error("authority request is invalid", 400);
    };
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    if control
        .validate(
            &deployment,
            &namespace,
            aos_hub_core::clock::now_unix_secs(),
        )
        .is_err()
    {
        return Response::error("authority request is outside configured domain", 400);
    }
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(
            worker::js_sys::Uint8Array::from(body.as_slice()).into(),
        ));
    let forwarded = Request::new_with_init("https://hybrid-authority/control", &init)?;
    let namespace_binding = env.durable_object(BINDING)?;
    let id = namespace_binding.id_from_name(LEDGER_NAME)?;
    id.get_stub()?.fetch_with_request(forwarded).await
}

fn configured_domain(env: &Env) -> Option<(String, String)> {
    let namespace = env.var(NAMESPACE_VARIABLE).ok()?.to_string();
    let executor = env.var(EXECUTOR_VARIABLE).ok()?.to_string();
    if namespace.is_empty() || executor.is_empty() {
        return None;
    }
    Some((namespace, executor))
}

// The fixed name makes changing a configured namespace label hit the existing
// durable domain pin instead of silently creating an empty admission ledger.
const LEDGER_NAME: &str = "physical-authority-ledger-v1";

async fn acquire_gate(gate: Arc<Mutex<()>>) -> OwnedMutexGuard<()> {
    loop {
        if let Some(permit) = gate.try_lock_owned() {
            return permit;
        }
        worker::Delay::from(Duration::from_millis(50)).await;
    }
}

fn storage_error(error: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError(error.to_string())
}

impl HybridAuthorityState {
    // Only the dedicated issuer role holds publisher authentication. A registry
    // acknowledgment means permanent reservation, never completed installation
    // or closed issuance; the actual per-authority reply supplies that result.
    async fn reserve_issuer(&self, mut request: Request) -> Result<Response> {
        let activate = request.url()?.path() == "/issuer-activate";
        use crate::hybrid_authority_state::AuthorityJournal as _;
        use aos_hub_core::storage_authority::control::{
            StorageAuthorityOperation, StorageAuthorityRequest,
        };
        use aos_hub_core::storage_authority::lease::control::IssuerOperation;

        let config = crate::hybrid_authority_issuer::IssuerConfiguration::load(&self.env)?;
        let (issuer, _, _) =
            crate::hybrid_authority_issuer::authenticated_request(&mut request, &self.env).await?;
        config.validate_installation(&issuer.installation)?;
        let binding = self.env.durable_object(BINDING)?;
        let expected = binding.id_from_name(LEDGER_NAME)?;
        anyhow::ensure!(
            expected.to_string() == self.state.id().to_string(),
            "registry address differs"
        );
        let _permit = acquire_gate(Arc::clone(&self.gate)).await;
        let installation_key = format!(
            "authority/{}/issuer-installation",
            issuer.installation.authority.authority_id.as_str()
        );
        let domain_key = "issuer-resource-domain-v1".to_owned();
        let domain = serde_json::json!({
            "resource": issuer.installation.issuer_resource_id,
            "runtime": issuer.installation.runtime_identity,
            "namespace": issuer.installation.authority.guard_namespace_id,
            "executor": issuer.installation.executor_identity,
        });
        let mut durable = DurableAuthorityJournal {
            storage: self.state.storage(),
            chunked: true,
        };
        let retained = durable.get(&installation_key).await?;
        if let Some(retained) = &retained {
            anyhow::ensure!(
                *retained == serde_json::to_value(&issuer.installation)?,
                "issuer resource attachment changed"
            );
        } else {
            anyhow::ensure!(
                matches!(issuer.operation, IssuerOperation::Install(_)),
                "fresh issuer installation required"
            );
            anyhow::ensure!(
                durable
                    .get(&format!(
                        "authority/{}/head",
                        issuer.installation.authority.authority_id.as_str()
                    ))
                    .await?
                    .is_none(),
                "used registry requires retained issuer attachment"
            );
        }
        if let Some(existing) = durable.get(&domain_key).await? {
            anyhow::ensure!(existing == domain, "permanent issuer resource changed");
        }
        let publication = match &issuer.operation {
            IssuerOperation::Install(publication) | IssuerOperation::Publish(publication) => {
                publication
            }
            IssuerOperation::Deny(transition) => &transition.publication,
            _ => anyhow::bail!("registry does not issue leases"),
        };
        let operation_key = format!(
            "authority/{}/issuer-control/{}",
            issuer.installation.authority.authority_id.as_str(),
            publication.generation
        );
        let retained_operation: Option<IssuerRegistryOperation> = durable
            .get(&operation_key)
            .await?
            .map(serde_json::from_value)
            .transpose()?;
        let input_digest = crate::hybrid_authority_issuer::operation_digest(&issuer.operation)?;
        let registry_predecessor = if let Some(retained) = &retained_operation {
            anyhow::ensure!(
                retained.operation_digest == input_digest,
                "issuer control replay changed semantic input"
            );
            retained.registry_predecessor.clone()
        } else if matches!(issuer.operation, IssuerOperation::Deny(_)) {
            durable
                .get(&format!(
                    "authority/{}/watermark",
                    issuer.installation.authority.authority_id.as_str()
                ))
                .await?
                .map(serde_json::from_value)
                .transpose()?
        } else {
            None
        };
        let operation = match &issuer.operation {
            IssuerOperation::Install(publication) | IssuerOperation::Publish(publication) => {
                StorageAuthorityOperation::Publish(publication.clone())
            }
            IssuerOperation::Deny(transition) => {
                let mut registry_transition = transition.clone();
                registry_transition.expected_remote = registry_predecessor.clone();
                StorageAuthorityOperation::DenyFromWatermark(registry_transition)
            }
            _ => anyhow::bail!("registry does not issue or renew leases"),
        };
        let operation_receipt = IssuerRegistryOperation {
            operation_digest: input_digest,
            registry_predecessor,
        };
        let control = StorageAuthorityRequest {
            version: 1,
            deployment_id: issuer.installation.runtime_identity.clone(),
            guard_namespace_id: issuer.installation.authority.guard_namespace_id.clone(),
            nonce: issuer.nonce.clone(),
            issued_at: issuer.issued_at.get(),
            expires_at: issuer.expires_at.get(),
            operation,
        };
        let mut reserved = IssuerReservationJournal {
            durable,
            installation_key,
            installation: serde_json::to_value(&issuer.installation)?,
            domain_key,
            domain,
            operation_key,
            operation_receipt: serde_json::to_value(operation_receipt)?,
        };
        let response = ledger::handle(
            &mut reserved,
            &control,
            &issuer.installation.runtime_identity,
            &issuer.installation.authority.guard_namespace_id,
            &issuer.installation.executor_identity,
            aos_hub_core::clock::now_unix_secs(),
        )
        .await?;
        anyhow::ensure!(
            response.control_receipt.is_some(),
            "registry control was not acknowledged"
        );
        // An exact replay must already retain the pin. Never add a pin after an
        // unconditional replay from legacy/current SQL metadata.
        anyhow::ensure!(
            reserved.durable.get(&reserved.installation_key).await? == Some(reserved.installation),
            "issuer reservation is missing"
        );
        anyhow::ensure!(
            reserved.durable.get(&reserved.operation_key).await?
                == Some(reserved.operation_receipt),
            "issuer operation receipt is missing"
        );
        let latest: aos_hub_core::storage_authority::control::StorageAuthorityPublication =
            reserved
                .durable
                .get(&format!(
                    "authority/{}/head",
                    issuer.installation.authority.authority_id.as_str()
                ))
                .await?
                .map(serde_json::from_value)
                .transpose()?
                .ok_or_else(|| anyhow::anyhow!("registry head missing after reservation"))?;
        let current_receipt = aos_hub_core::storage_authority::lease::control::IssuerPublicationReceipt::from_publication(&latest)?;
        let activated_key = format!(
            "authority/{}/issuer-activated-v1",
            issuer.installation.authority.authority_id.as_str()
        );
        let mut activation: Option<crate::hybrid_authority_issuer::ActivatedIssuerReceipt> =
            reserved
                .durable
                .get(&activated_key)
                .await?
                .map(serde_json::from_value)
                .transpose()?;
        if activate {
            let IssuerOperation::Install(initial) = &issuer.operation else {
                anyhow::bail!("activation requires exact initial installation");
            };
            anyhow::ensure!(
                initial.generation == 1,
                "activation requires initial publication"
            );
            let expected = crate::hybrid_authority_issuer::ActivatedIssuerReceipt {
                installation: issuer.installation.clone(),
                initial_receipt: aos_hub_core::storage_authority::lease::control::IssuerPublicationReceipt::from_publication(initial)?,
                initial_operation_digest: crate::hybrid_authority_issuer::operation_digest(&issuer.operation)?,
            };
            anyhow::ensure!(
                current_receipt == expected.initial_receipt,
                "registry advanced beyond pending installation"
            );
            if let Some(existing) = &activation {
                anyhow::ensure!(*existing == expected, "issuer activation changed");
            } else {
                reserved
                    .durable
                    .put_atomic(BTreeMap::from([(
                        activated_key,
                        serde_json::to_value(&expected)?,
                    )]))
                    .await?;
                activation = Some(expected);
            }
        }
        if let Some(activation) = &activation {
            anyhow::ensure!(
                activation.installation == issuer.installation,
                "activated issuer attachment changed"
            );
        }
        Ok(Response::from_json(
            &crate::hybrid_authority_issuer::IssuerReservationReply {
                current_receipt,
                activation,
            },
        )?)
    }
}

struct IssuerReservationJournal {
    durable: DurableAuthorityJournal,
    installation_key: String,
    installation: Value,
    domain_key: String,
    domain: Value,
    operation_key: String,
    operation_receipt: Value,
}

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerRegistryOperation {
    operation_digest: String,
    registry_predecessor: Option<aos_hub_core::storage_authority::StorageAuthorityRemoteWatermark>,
}

impl ledger::AuthorityJournal for IssuerReservationJournal {
    async fn get(&mut self, key: &str) -> Result<Option<Value>> {
        self.durable.get(key).await
    }

    async fn put_atomic(&mut self, mut values: BTreeMap<String, Value>) -> Result<()> {
        values.insert(self.installation_key.clone(), self.installation.clone());
        values.insert(self.domain_key.clone(), self.domain.clone());
        values.insert(self.operation_key.clone(), self.operation_receipt.clone());
        self.durable.put_atomic(values).await
    }
}
