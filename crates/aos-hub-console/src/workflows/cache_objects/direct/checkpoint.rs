//! Private IndexedDB records acknowledged before direct upload control effects.
//!
//! Each transaction contains at most 64 bounded records. Cancellation clears
//! event handlers and aborts an unacknowledged transaction; an already committed
//! write remains history and is read on resume. No provider capability is stored.

use std::{cell::RefCell, rc::Rc};

use futures::channel::oneshot;
use serde::de::DeserializeOwned;

use crate::direct_upload_model::{CheckpointRecord, PartCheckpoint, ResumeHead};
use wasm_bindgen::{closure::Closure, prelude::wasm_bindgen, JsCast, JsValue};
use web_sys::{Event, EventTarget, IdbDatabase, IdbRequest, IdbTransaction};

const DATABASE: &str = "aos-direct-upload-resume-v1";
const STORE: &str = "records";
const FAILURE: &str =
    "The browser could not retain upload progress; enable private browser storage";

type Completion = Result<(), String>;
type Sender = Rc<RefCell<Option<oneshot::Sender<Completion>>>>;

struct EventWait {
    target: EventTarget,
    handlers: Vec<(EventTarget, &'static str, Closure<dyn FnMut(Event)>)>,
    sender: Sender,
    receiver: oneshot::Receiver<Completion>,
}

impl EventWait {
    fn new(
        target: &EventTarget,
        success: &'static str,
        failures: &[&'static str],
    ) -> Result<Self, String> {
        let (sender, receiver) = oneshot::channel();
        let mut wait = Self {
            target: target.clone(),
            handlers: Vec::new(),
            sender: Rc::new(RefCell::new(Some(sender))),
            receiver,
        };
        for (name, result) in std::iter::once((success, Ok(()))).chain(
            failures
                .iter()
                .map(|name| (*name, Err(FAILURE.to_string()))),
        ) {
            let sender = wait.sender.clone();
            wait.add(
                name,
                Closure::wrap(Box::new(move |_: Event| {
                    let completion = sender.borrow_mut().take();
                    if let Some(sender) = completion {
                        let _ = sender.send(result.clone());
                    }
                }) as Box<dyn FnMut(Event)>),
            )?;
        }
        Ok(wait)
    }

    fn add(
        &mut self,
        name: &'static str,
        handler: Closure<dyn FnMut(Event)>,
    ) -> Result<(), String> {
        self.add_on(self.target.clone(), name, handler)
    }

    fn add_on(
        &mut self,
        target: EventTarget,
        name: &'static str,
        handler: Closure<dyn FnMut(Event)>,
    ) -> Result<(), String> {
        target
            .add_event_listener_with_callback(name, handler.as_ref().unchecked_ref())
            .map_err(|_| FAILURE.to_string())?;
        self.handlers.push((target, name, handler));
        Ok(())
    }

    async fn wait(mut self) -> Completion {
        (&mut self.receiver)
            .await
            .map_err(|_| FAILURE.to_string())?
    }
}

impl Drop for EventWait {
    fn drop(&mut self) {
        for (target, name, handler) in &self.handlers {
            let _ =
                target.remove_event_listener_with_callback(name, handler.as_ref().unchecked_ref());
        }
    }
}

struct WriteGuard {
    transaction: IdbTransaction,
    acknowledged: bool,
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        if !self.acknowledged {
            let _ = self.transaction.abort();
        }
    }
}

/// Owns the private browser resume database connection.
pub(super) struct Checkpoint {
    database: IdbDatabase,
}

impl Drop for Checkpoint {
    fn drop(&mut self) {
        self.database.close();
    }
}

impl Checkpoint {
    /// Opens the existing versioned database or initializes its empty record store.
    ///
    /// # Errors
    /// Returns an error for blocked/unavailable storage or an incompatible store.
    pub(super) async fn open() -> Result<Self, String> {
        let factory = web_sys::window()
            .ok_or_else(|| FAILURE.to_string())?
            .indexed_db()
            .map_err(|_| FAILURE.to_string())?
            .ok_or_else(|| FAILURE.to_string())?;
        let request = factory
            .open_with_u32(DATABASE, 1)
            .map_err(|_| FAILURE.to_string())?;
        let mut wait = EventWait::new(request.unchecked_ref(), "success", &["error", "blocked"])?;
        let upgrade_request = request.clone();
        let sender = wait.sender.clone();
        wait.add(
            "upgradeneeded",
            Closure::wrap(Box::new(move |_: Event| {
                let result = upgrade_request
                    .result()
                    .ok()
                    .and_then(|value| value.dyn_into::<IdbDatabase>().ok());
                let created = result.as_ref().is_some_and(|database| {
                    database.object_store_names().contains(STORE)
                        || database.create_object_store(STORE).is_ok()
                });
                if !created {
                    if let Some(transaction) = upgrade_request.transaction() {
                        let _ = transaction.abort();
                    }
                    if let Some(sender) = sender.borrow_mut().take() {
                        let _ = sender.send(Err(FAILURE.to_string()));
                    }
                }
            }) as Box<dyn FnMut(Event)>),
        )?;
        wait.wait().await?;
        let database = request
            .result()
            .map_err(|_| FAILURE.to_string())?
            .dyn_into::<IdbDatabase>()
            .map_err(|_| FAILURE.to_string())?;
        if !database.object_store_names().contains(STORE) {
            database.close();
            return Err(FAILURE.to_string());
        }
        Ok(Self { database })
    }

    /// Reads one closed bounded resume record.
    ///
    /// # Errors
    /// Returns an error for failed reads or malformed retained records.
    pub(super) async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, String> {
        let transaction = self
            .database
            .transaction_with_str(STORE)
            .map_err(|_| FAILURE.to_string())?;
        let request = transaction
            .object_store(STORE)
            .map_err(|_| FAILURE.to_string())?
            .get(&JsValue::from_str(key))
            .map_err(|_| FAILURE.to_string())?;
        EventWait::new(request.unchecked_ref(), "success", &["error"])?
            .wait()
            .await?;
        decode(request)
    }

    /// Atomically preserves immutable intent and previously acknowledged history.
    ///
    /// # Errors
    /// Returns an error for unavailable storage, changed identity or failed commit.
    pub(super) async fn put<T: CheckpointRecord + 'static>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<T, String> {
        let mut merged = self.merge_wave(&[(key.to_string(), value.clone())]).await?;
        merged.pop().ok_or_else(|| FAILURE.to_string())
    }

    /// Commits a bounded wave of original part records in one write transaction.
    ///
    /// # Errors
    /// Returns an error for invalid records, changed receipts or failed commit.
    pub(super) async fn put_wave(&self, records: &[(String, Vec<u8>)]) -> Result<(), String> {
        let records: Vec<(String, PartCheckpoint)> = records
            .iter()
            .map(|(key, bytes)| {
                aos_proto_types::direct_upload::decode_direct_control(bytes)
                    .map(|value| (key.clone(), value))
                    .map_err(|_| FAILURE.to_string())
            })
            .collect::<Result<_, _>>()?;
        self.merge_wave(&records).await?;
        Ok(())
    }

    async fn merge_wave<T: CheckpointRecord + 'static>(
        &self,
        records: &[(String, T)],
    ) -> Result<Vec<T>, String> {
        use aos_proto_types::direct_upload::{
            encode_direct_control, MAX_DIRECT_BATCH_ITEMS, MAX_DIRECT_CONTROL_BYTES,
        };
        let mut keys = std::collections::HashSet::new();
        let mut input_bytes = 0_usize;
        for (key, value) in records {
            if !keys.insert(key) {
                return Err(FAILURE.to_string());
            }
            input_bytes = input_bytes
                .checked_add(key.len())
                .and_then(|total| {
                    encode_direct_control(value)
                        .ok()
                        .and_then(|bytes| total.checked_add(bytes.len()))
                })
                .ok_or_else(|| FAILURE.to_string())?;
        }
        if records.is_empty()
            || records.len() > MAX_DIRECT_BATCH_ITEMS
            || input_bytes > MAX_DIRECT_CONTROL_BYTES
        {
            return Err(FAILURE.to_string());
        }

        let transaction = self.write_transaction()?;
        let mut guard = WriteGuard {
            transaction,
            acknowledged: false,
        };
        let mut wait = EventWait::new(
            guard.transaction.unchecked_ref(),
            "complete",
            &["error", "abort"],
        )?;
        let store = guard
            .transaction
            .object_store(STORE)
            .map_err(|_| FAILURE.to_string())?;
        let merged: Rc<RefCell<Vec<Option<T>>>> = Rc::new(RefCell::new(vec![None; records.len()]));
        let total = Rc::new(RefCell::new(0_usize));
        for (index, (key, value)) in records.iter().enumerate() {
            // Request callbacks run while this SAME read/write transaction is active.
            // Awaiting individual reads would relinquish its atomic merge boundary.
            let request = store
                .get(&JsValue::from_str(key))
                .map_err(|_| FAILURE.to_string())?;
            let request_copy = request.clone();
            let value = value.clone();
            let key = key.clone();
            let store = store.clone();
            let transaction = guard.transaction.clone();
            let sender = wait.sender.clone();
            let merged = merged.clone();
            let total = total.clone();
            wait.add_on(
                request.unchecked_into(),
                "success",
                Closure::wrap(Box::new(move |_: Event| {
                    let result = (|| {
                        let next = value.clone().merge(decode(request_copy.clone())?)?;
                        let bytes =
                            encode_direct_control(&next).map_err(|_| FAILURE.to_string())?;
                        let size = total
                            .borrow()
                            .checked_add(key.len())
                            .and_then(|size| size.checked_add(bytes.len()))
                            .filter(|size| *size <= MAX_DIRECT_CONTROL_BYTES)
                            .ok_or_else(|| FAILURE.to_string())?;
                        let json = std::str::from_utf8(&bytes).map_err(|_| FAILURE.to_string())?;
                        store
                            .put_with_key(&JsValue::from_str(json), &JsValue::from_str(&key))
                            .map_err(|_| FAILURE.to_string())?;
                        *total.borrow_mut() = size;
                        merged.borrow_mut()[index] = Some(next);
                        Ok::<_, String>(())
                    })();
                    if let Err(error) = result {
                        let _ = transaction.abort();
                        let completion = sender.borrow_mut().take();
                        if let Some(sender) = completion {
                            let _ = sender.send(Err(error));
                        }
                    }
                }) as Box<dyn FnMut(Event)>),
            )?;
        }
        wait.wait().await?;
        guard.acknowledged = true;
        let result = merged
            .borrow_mut()
            .iter_mut()
            .map(|value| value.take().ok_or_else(|| FAILURE.to_string()))
            .collect();
        result
    }

    fn write_transaction(&self) -> Result<IdbTransaction, String> {
        // The pinned web-sys exposes this standardized overload behind its broad
        // unstable-API flag. Bind only this overload, rather than changing the
        // build configuration or accepting default relaxed durability.
        let options = js_sys::Object::new();
        js_sys::Reflect::set(
            &options,
            &JsValue::from_str("durability"),
            &JsValue::from_str("strict"),
        )
        .map_err(|_| FAILURE.to_string())?;
        let database: &StrictDatabase = self.database.unchecked_ref();
        let transaction = database
            .transaction_strict(STORE, "readwrite", options.as_ref())
            .map_err(|_| FAILURE.to_string())?;
        let durability =
            js_sys::Reflect::get(transaction.as_ref(), &JsValue::from_str("durability"))
                .map_err(|_| FAILURE.to_string())?;
        if durability.as_string().as_deref() != Some("strict") {
            let _ = transaction.abort();
            return Err(FAILURE.to_string());
        }
        Ok(transaction)
    }

    /// Removes the active pointer only for the exact retained committed run.
    ///
    /// # Errors
    /// Returns an error if another run owns the pointer or its transaction fails.
    pub(super) async fn retire_active(
        &self,
        key: &str,
        expected: &ResumeHead,
    ) -> Result<(), String> {
        let transaction = self.write_transaction()?;
        let mut guard = WriteGuard {
            transaction,
            acknowledged: false,
        };
        let mut wait = EventWait::new(
            guard.transaction.unchecked_ref(),
            "complete",
            &["error", "abort"],
        )?;
        let store = guard
            .transaction
            .object_store(STORE)
            .map_err(|_| FAILURE.to_string())?;
        let request = store
            .get(&JsValue::from_str(key))
            .map_err(|_| FAILURE.to_string())?;
        let copy = request.clone();
        let expected = expected.clone();
        let key = key.to_string();
        let transaction = guard.transaction.clone();
        let sender = wait.sender.clone();
        wait.add_on(
            request.unchecked_into(),
            "success",
            Closure::wrap(Box::new(move |_: Event| {
                let result = (|| {
                    let Some(retained): Option<ResumeHead> = decode(copy.clone())? else {
                        return Ok(());
                    };
                    if retained.scope != expected.scope
                        || retained.run_nonce != expected.run_nonce
                        || retained.intent != expected.intent
                        || retained.principal_id != expected.principal_id
                        || retained.deployment_id != expected.deployment_id
                        || retained.session.as_ref().is_none_or(|status| {
                            status.state
                                != aos_proto_types::direct_upload::DirectSessionState::Committed
                        })
                    {
                        return Err("The browser upload pointer belongs to another retained run"
                            .to_string());
                    }
                    store
                        .delete(&JsValue::from_str(&key))
                        .map_err(|_| FAILURE.to_string())?;
                    Ok::<_, String>(())
                })();
                if let Err(error) = result {
                    let _ = transaction.abort();
                    let completion = sender.borrow_mut().take();
                    if let Some(sender) = completion {
                        let _ = sender.send(Err(error));
                    }
                }
            }) as Box<dyn FnMut(Event)>),
        )?;
        wait.wait().await?;
        guard.acknowledged = true;
        Ok(())
    }
}

fn decode<T: DeserializeOwned>(request: IdbRequest) -> Result<Option<T>, String> {
    let value = request.result().map_err(|_| FAILURE.to_string())?;
    if value.is_undefined() {
        return Ok(None);
    }
    let json = value.as_string().ok_or_else(|| FAILURE.to_string())?;
    aos_proto_types::direct_upload::decode_direct_control(json.as_bytes())
        .map(Some)
        .map_err(|_| {
            "The browser upload checkpoint is invalid; original progress was preserved".to_string()
        })
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Object, js_name = IDBDatabase)]
    type StrictDatabase;

    #[wasm_bindgen(catch, method, js_name = transaction)]
    fn transaction_strict(
        this: &StrictDatabase,
        store: &str,
        mode: &str,
        options: &JsValue,
    ) -> Result<IdbTransaction, JsValue>;
}
