//! The Durable Object implementation of the shared [`Coordinator`] port
//! (wasm32-only).
//!
//! RFC-0004 chapter 14 routes the hub's *atomic* state — fixed-window rate
//! limits, the publish lease, channel anti-rollback floors — off D1 and onto a
//! **Durable Object**, whose single global instance and serialized execution
//! give strict serializability without a per-request SQL round-trip (and without
//! a write on the read path). Workers KV cannot serve this (eventually
//! consistent, ~1 write/sec/key, no atomic increment).
//!
//! Two pieces live here:
//!
//! - [`CoordinatorObject`] — the Durable Object class. Its `fetch` decodes a
//!   [`Command`] and runs it against the DO's transactional storage
//!   (`state.storage()`), so all of a deployment's coordinator operations,
//!   routed to one instance ([`COORDINATOR_INSTANCE`]), are serialized.
//! - [`WorkerCoordinator`] — the client: an
//!   [`aos_hub_core::coordinator::Coordinator`] that forwards each operation to
//!   the DO over its stub. The native hub uses the in-process
//!   [`InMemoryCoordinator`](aos_hub_core::coordinator::InMemoryCoordinator)
//!   behind the same port.
//!
//! # Storage keys
//!
//! ```text
//! c:{class}:{key}:{window}  -> i64   fixed-window attempt count
//! l:{key}                   -> Lease holder + deadline (publish lease)
//! f:{key}                   -> i64   monotonic floor (channel anti-rollback)
//! ```
//!
//! The wire format between client and DO is a small JSON [`Command`] /
//! [`CmdReply`]; the DO is reached at a synthetic `https://coordinator/` URL
//! (the host/path are irrelevant — the stub routes by object id, not URL).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{
    durable_object, DurableObject, Env, Method, ObjectNamespace, Request, RequestInit, Response,
    State,
};

use aos_hub_core::coordinator::Coordinator;

/// The single DO instance every coordinator operation routes to.
///
/// One instance serializes all of a deployment's rate-limit/lease/floor
/// operations. (Per-tenant sharding — a DO per registry — is RFC-0004 ch.14
/// Phase E, where the tenant DO also owns the tenant's SQLite state.)
const COORDINATOR_INSTANCE: &str = "global";

/// A coordinator operation, sent as JSON from [`WorkerCoordinator`] to the DO.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Command {
    /// Record one attempt in `window` for `(class, key)` against `budget`.
    Admit {
        class: String,
        key: String,
        window: i64,
        budget: i64,
    },
    /// Acquire/refresh the lease at `key` for `holder` (deadline `now + ttl`).
    AcquireLease {
        key: String,
        holder: String,
        ttl: i64,
        now: i64,
    },
    /// Release the lease at `key` iff `holder` holds it.
    ReleaseLease { key: String, holder: String },
    /// Store `value` at floor `key` iff it strictly exceeds the current floor.
    AdvanceFloor { key: String, value: i64 },
}

/// The DO's reply: each field is set only for the operation it answers.
#[derive(Debug, Default, Serialize, Deserialize)]
struct CmdReply {
    /// `admit`: whether the attempt was admitted.
    #[serde(default)]
    admitted: Option<bool>,
    /// `acquire_lease`: the conflicting holder, when a different holder's lease
    /// is live; `None` on success.
    #[serde(default)]
    conflict: Option<String>,
    /// `advance_floor`: whether the floor was advanced.
    #[serde(default)]
    accepted: Option<bool>,
}

/// A stored lease: holder and the unix-second deadline.
#[derive(Debug, Serialize, Deserialize)]
struct Lease {
    holder: String,
    deadline: i64,
}

/// The coordinator Durable Object: serializes counters, leases, and floors.
#[durable_object]
pub struct CoordinatorObject {
    state: State,
}

impl DurableObject for CoordinatorObject {
    fn new(state: State, _env: Env) -> Self {
        CoordinatorObject { state }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        let cmd: Command = req.json().await?;
        let storage = self.state.storage();
        let reply = match cmd {
            Command::Admit {
                class,
                key,
                window,
                budget,
            } => {
                let skey = format!("c:{class}:{key}:{window}");
                let current: i64 = storage.get(&skey).await.unwrap_or(None).unwrap_or(0);
                let admitted = current < budget;
                if admitted {
                    storage.put(&skey, current + 1).await?;
                }
                CmdReply {
                    admitted: Some(admitted),
                    ..Default::default()
                }
            }
            Command::AcquireLease {
                key,
                holder,
                ttl,
                now,
            } => {
                let skey = format!("l:{key}");
                let existing: Option<Lease> = storage.get(&skey).await.unwrap_or(None);
                match existing {
                    Some(lease) if lease.deadline > now && lease.holder != holder => CmdReply {
                        conflict: Some(lease.holder),
                        ..Default::default()
                    },
                    _ => {
                        storage
                            .put(
                                &skey,
                                Lease {
                                    holder,
                                    deadline: now + ttl,
                                },
                            )
                            .await?;
                        CmdReply::default()
                    }
                }
            }
            Command::ReleaseLease { key, holder } => {
                let skey = format!("l:{key}");
                let existing: Option<Lease> = storage.get(&skey).await.unwrap_or(None);
                if existing.is_some_and(|lease| lease.holder == holder) {
                    storage.delete(&skey).await?;
                }
                CmdReply::default()
            }
            Command::AdvanceFloor { key, value } => {
                let skey = format!("f:{key}");
                let current: Option<i64> = storage.get(&skey).await.unwrap_or(None);
                let accepted = current.is_none_or(|c| value > c);
                if accepted {
                    storage.put(&skey, value).await?;
                }
                CmdReply {
                    accepted: Some(accepted),
                    ..Default::default()
                }
            }
        };
        Response::from_json(&reply)
    }
}

/// A [`Coordinator`] that forwards each operation to the [`CoordinatorObject`]
/// Durable Object over its stub.
///
/// Built per request from the bound DO namespace; every operation routes to the
/// single [`COORDINATOR_INSTANCE`] so they are globally serialized.
pub struct WorkerCoordinator {
    namespace: ObjectNamespace,
}

impl WorkerCoordinator {
    /// Builds the client from the Worker environment's DO binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the `COORDINATOR` Durable Object binding is missing.
    pub fn from_env(env: &Env) -> worker::Result<WorkerCoordinator> {
        Ok(WorkerCoordinator {
            namespace: env.durable_object(crate::handlers::bindings::COORDINATOR)?,
        })
    }

    /// Sends one [`Command`] to the DO and decodes its [`CmdReply`].
    async fn call(&self, cmd: &Command) -> anyhow::Result<CmdReply> {
        let stub = self
            .namespace
            .id_from_name(COORDINATOR_INSTANCE)
            .and_then(|id| id.get_stub())
            .map_err(|err| anyhow::anyhow!("coordinator stub: {err}"))?;
        let body = serde_json::to_string(cmd)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_body(Some(JsValue::from_str(&body)));
        let req = Request::new_with_init("https://coordinator/", &init)
            .map_err(|err| anyhow::anyhow!("coordinator request: {err}"))?;
        let mut resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|err| anyhow::anyhow!("coordinator fetch: {err}"))?;
        resp.json::<CmdReply>()
            .await
            .map_err(|err| anyhow::anyhow!("coordinator reply: {err}"))
    }
}

#[async_trait(?Send)]
impl Coordinator for WorkerCoordinator {
    async fn admit(
        &self,
        class: &str,
        key: &str,
        window: i64,
        budget: i64,
    ) -> anyhow::Result<bool> {
        let reply = self
            .call(&Command::Admit {
                class: class.to_string(),
                key: key.to_string(),
                window,
                budget,
            })
            .await?;
        Ok(reply.admitted.unwrap_or(true))
    }

    async fn acquire_lease(
        &self,
        key: &str,
        holder: &str,
        ttl_secs: i64,
        now: i64,
    ) -> anyhow::Result<Option<String>> {
        let reply = self
            .call(&Command::AcquireLease {
                key: key.to_string(),
                holder: holder.to_string(),
                ttl: ttl_secs,
                now,
            })
            .await?;
        Ok(reply.conflict)
    }

    async fn release_lease(&self, key: &str, holder: &str) -> anyhow::Result<()> {
        self.call(&Command::ReleaseLease {
            key: key.to_string(),
            holder: holder.to_string(),
        })
        .await
        .map(|_| ())
    }

    async fn advance_floor(&self, key: &str, value: i64) -> anyhow::Result<bool> {
        let reply = self
            .call(&Command::AdvanceFloor {
                key: key.to_string(),
                value,
            })
            .await?;
        Ok(reply.accepted.unwrap_or(false))
    }
}
