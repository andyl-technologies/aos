//! Commits one serialized journal turn as a bounded durable write batch.
//!
//! Reads keep using the retained journal. Writes become visible together before
//! the caller can return a dispatch permit. Refused operations retain only their
//! advanced clock floor, so invalid requests cannot roll the observed clock back.

use anyhow::{ensure, Result};
use aos_hub_db::direct_upload::{encode_direct_control, WireInteger};
use serde::Serialize;
use wasm_bindgen::JsValue;
use worker::Storage;

const CLOCK: &str = "clock-floor/v1";
const MAX_RECORDS: usize = 2;

pub(super) struct Turn<'a> {
    storage: &'a Storage,
    clock: Option<String>,
    records: Vec<(String, String)>,
}

impl<'a> Turn<'a> {
    pub(super) async fn new(storage: &'a Storage, now: u64) -> Result<Self> {
        let floor = super::read::<WireInteger>(storage, CLOCK).await?;
        ensure!(
            floor.is_none_or(|floor| now >= floor.get()),
            "direct durable clock regressed"
        );
        let clock = if floor.is_some_and(|floor| floor.get() == now) {
            None
        } else {
            Some(encode(&WireInteger::new(now))?)
        };
        Ok(Self {
            storage,
            clock,
            records: Vec::new(),
        })
    }

    pub(super) fn storage(&self) -> &Storage {
        self.storage
    }

    pub(super) async fn read<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        if let Some((_, value)) = self.records.iter().find(|(retained, _)| retained == key) {
            return Ok(Some(serde_json::from_str(value)?));
        }
        super::read(self.storage, key).await
    }

    pub(super) fn write<T: Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
        ensure!(
            key != CLOCK && !self.records.iter().any(|(retained, _)| retained == key),
            "direct journal turn repeats a retained key"
        );
        ensure!(
            self.records.len() < MAX_RECORDS,
            "direct journal turn exceeds record bound"
        );
        self.records.push((key.to_owned(), encode(value)?));
        Ok(())
    }

    pub(super) async fn commit(self, accepted: bool) -> Result<()> {
        let values = js_sys::Object::new();
        let mut count = 0;
        if let Some(clock) = self.clock {
            set(&values, CLOCK, &clock)?;
            count += 1;
        }
        if accepted {
            for (key, value) in self.records {
                set(&values, &key, &value)?;
                count += 1;
            }
        }
        if count > 0 {
            // A plain JS object avoids the SDK's Map enumeration mismatch.
            // The single put atomically retains the attempt and effect before
            // a successful reply can permit any provider dispatch.
            self.storage.put_multiple_raw(values).await?;
        }
        Ok(())
    }
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    let encoded = encode_direct_control(value)?;
    ensure!(
        encoded.len() <= 128 * 1024,
        "direct retained record exceeds bound"
    );
    Ok(String::from_utf8(encoded)?)
}

fn set(values: &js_sys::Object, key: &str, value: &str) -> Result<()> {
    let retained = js_sys::Reflect::set(values, &JsValue::from_str(key), &JsValue::from_str(value))
        .map_err(|_| anyhow::anyhow!("direct journal batch encoding failed"))?;
    ensure!(retained, "direct journal batch key refused");
    Ok(())
}
