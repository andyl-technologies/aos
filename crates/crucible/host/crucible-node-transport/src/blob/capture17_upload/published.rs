//! Checks immutable completed upload custody without asserting old state is current.
//!
//! A published ancestor remains valid when later uploads advance the same Blob
//! ledger. Only the separate current-receiver check compares its saved after
//! stamp with that ledger. Neither check creates a spent action or Source right.

use super::*;
use serde_json::{Map, Value};

fn string(value: Option<&Value>, expected: &str) -> bool {
    value.and_then(Value::as_str) == Some(expected)
}

fn integer(value: Option<&Value>, expected: U64) -> bool {
    let Some(text) = value.and_then(Value::as_str) else {
        return false;
    };
    !text.is_empty()
        && text.len() <= 20
        && (text.len() == 1 || !text.starts_with('0'))
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && text.parse::<u64>().ok() == Some(expected.get())
}

fn reference(value: Option<&Value>, expected: &ContentRef) -> bool {
    let Some(value) = value.and_then(Value::as_object) else {
        return false;
    };
    let ContentRef {
        hash,
        length,
        media_type,
    } = expected;
    let crucible_node_format::HashRef {
        algorithm,
        domain,
        digest,
    } = hash;
    let Some(hash) = value.get("hash").and_then(Value::as_object) else {
        return false;
    };
    value.len() == 3
        && hash.len() == 3
        && string(hash.get("algorithm"), algorithm)
        && string(hash.get("domain"), domain)
        && string(hash.get("digest"), digest)
        && integer(value.get("length"), *length)
        && string(value.get("media_type"), media_type)
}

fn authenticate_reply(
    reply: &Map<String, Value>,
    input: NativeCapture17UploadInput<'_>,
    result: &UploadResult,
) -> Result<(), ProviderError> {
    if reply.len() != 4
        || !string(reply.get("status"), "completed")
        || !string(reply.get("operation_state"), "completed")
        || !reply
            .get("extensions")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
    {
        return Err(refused());
    }
    let body = reply
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let key = input.key_data();
    let matches = match (input, result) {
        (NativeCapture17UploadInput::Begin { .. }, UploadResult::Progress(progress)) => {
            body.len() == 3
                && progress.transfer_id == *key.transfer
                && string(body.get("transfer_id"), progress.transfer_id.as_str())
                && integer(body.get("next_offset"), progress.next_offset)
                && integer(
                    body.get("maximum_chunk_bytes"),
                    progress.maximum_chunk_bytes,
                )
        }
        (NativeCapture17UploadInput::Chunk { .. }, UploadResult::Progress(progress)) => {
            body.len() == 2
                && progress.transfer_id == *key.transfer
                && string(body.get("transfer_id"), progress.transfer_id.as_str())
                && integer(body.get("next_offset"), progress.next_offset)
        }
        (NativeCapture17UploadInput::Finish { .. }, UploadResult::Verified(verified)) => {
            body.len() == 2
                && key.same_data(&verified.key)
                && string(body.get("transfer_id"), verified.key.transfer.as_str())
                && reference(body.get("content"), &verified.content)
        }
        _ => false,
    };
    if !matches {
        return Err(refused());
    }
    Ok(())
}

impl NativeCapture17UploadAttempt {
    /// Checks the immutable normal result against its actual quotation and input.
    ///
    /// This deliberately does not compare the saved after stamp with today's
    /// ledger: an earlier completed Begin remains an ancestor after later Chunks.
    /// The owning native bank and its real publication record remain separate.
    ///
    /// # Errors
    /// Refuses incomplete/failed custody, different ledger/supervisor/input or
    /// quote, absent poststate, wrong result branch, or changed closed reply.
    pub(crate) fn authenticate_completed_quotation17_data(
        &self,
        storage: &NativeCapture17UploadStorageData,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.owner, &storage.owner)
            || !Rc::ptr_eq(&self.supervisor, &storage.supervisor)
            || self.before != storage.before
            || self.input != storage.input
            || self.input != identity::input_data(input)?
            || self.after.is_none()
        {
            return Err(refused());
        }
        let result = self.result.as_ref().ok_or_else(refused)?;
        if let UploadResult::Verified(verified) = result
            && !Rc::ptr_eq(&verified.receiver, &self.owner)
        {
            return Err(refused());
        }
        authenticate_reply(self.reply_data()?, input, result)
    }

    /// Checks the immediately preceding upload's real poststate against its receiver.
    ///
    /// This stricter check is for a live latest-occurrence lender. Calling it on
    /// an older ancestor after legitimate later progress will refuse. It neither
    /// repeats the old before-state predicate nor grants a continuation action.
    ///
    /// # Errors
    /// Refuses incomplete or changed quotation/result, another receiver or any
    /// difference from the actual saved complete after-state transcript.
    pub(crate) fn authenticate_current_completed_receiver17_data(
        &self,
        receiver: &BlobReceiver,
        storage: &NativeCapture17UploadStorageData,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_completed_quotation17_data(storage, input)?;
        self.authenticate_result_data(receiver, storage, input)
    }

    /// Borrows retained progress DATA without manufacturing a successful result.
    pub(crate) fn completed_progress17_data(&self) -> Option<&BlobProgress> {
        if self.phase != UploadPhase::ReplyComplete {
            return None;
        }
        match &self.result {
            Some(UploadResult::Progress(progress)) => Some(progress),
            _ => None,
        }
    }

    /// Names the immutable completion/input/reply and current-state check views.
    pub(crate) fn completed_quotation17_counter_scratch_data() -> usize {
        identity::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&NativeCapture17UploadStorageData>()
            + size_of::<NativeCapture17UploadInput<'static>>()
            + size_of::<&UploadResult>()
            + size_of::<&BlobProgress>()
            + size_of::<Option<&BlobProgress>>()
            + size_of::<&VerifiedTransfer>()
            + size_of::<Option<&VerifiedTransfer>>()
            + size_of::<&Map<String, Value>>() * 3
            + size_of::<Option<&Value>>()
            + size_of::<Option<&str>>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<Result<u64, std::num::ParseIntError>>()
            + size_of::<(&crucible_node_format::HashRef, &U64, &String)>()
            + size_of::<(&String, &String, &String)>()
            + size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Supervisor;

    impl BlobSupervisor for Supervisor {
        fn quarantine(&self, _: BlobQuarantine) {}
    }

    #[test]
    fn closed_reply_correspondence_checks_actual_primitive_results() -> Result<(), ProviderError> {
        // These are ordinary Blob primitives and inert reply DATA. No native
        // attempt, spent token or successful publication is manufactured.
        let session = Id::new("session")?;
        let incarnation = Id::new("incarnation")?;
        let key = TransferKey {
            origin: RequestOrigin::Controller,
            session: session.clone(),
            incarnation: incarnation.clone(),
            transfer: Id::new("transfer")?,
        };
        let borrowed_key = NativeCapture17UploadKey {
            origin: key.origin,
            session: &key.session,
            incarnation: &key.incarnation,
            transfer: &key.transfer,
        };
        let mut receiver = BlobReceiver::new(
            session,
            incarnation,
            BlobLimits {
                reserved_bytes: 1024,
                content_bytes: 1024,
                chunk_bytes: 64,
                transfers_per_origin: 4,
                tombstones_per_origin: 4,
                chunks_per_transfer: 4,
                operation_pins: 4,
            },
            Rc::new(Supervisor),
        )?;
        let bytes = Bytes::new(b"actual primitive result".to_vec());
        let content = crucible_node_format::canonical::content_ref(
            bytes.as_slice(),
            "application/octet-stream",
        )?;
        let begin_input = NativeCapture17UploadInput::Begin {
            key: borrowed_key,
            content: &content,
        };
        let progress = receiver.begin(key.clone(), content.clone())?;
        let mut begin = json!({
            "status":"completed", "operation_state":"completed",
            "result":{
                "transfer_id":progress.transfer_id,
                "next_offset":progress.next_offset,
                "maximum_chunk_bytes":progress.maximum_chunk_bytes,
            },
            "extensions":{},
        });
        let result = UploadResult::Progress(progress);
        authenticate_reply(begin.as_object().ok_or_else(refused)?, begin_input, &result)?;
        begin["result"]["next_offset"] = json!("00");
        assert!(
            authenticate_reply(begin.as_object().ok_or_else(refused)?, begin_input, &result)
                .is_err()
        );
        begin["result"]["next_offset"] = json!("0");
        begin["result"]["extra"] = Value::Null;
        assert!(
            authenticate_reply(begin.as_object().ok_or_else(refused)?, begin_input, &result)
                .is_err()
        );

        let chunk_input = NativeCapture17UploadInput::Chunk {
            key: borrowed_key,
            offset: U64::new(0),
            bytes: &bytes,
        };
        let progress = receiver.chunk(&key, U64::new(0), &bytes)?;
        let chunk = json!({
            "status":"completed", "operation_state":"completed",
            "result":{"transfer_id":progress.transfer_id,"next_offset":progress.next_offset},
            "extensions":{},
        });
        let result = UploadResult::Progress(progress);
        authenticate_reply(chunk.as_object().ok_or_else(refused)?, chunk_input, &result)?;
        assert!(
            authenticate_reply(chunk.as_object().ok_or_else(refused)?, begin_input, &result)
                .is_err()
        );

        let verified = receiver.finish(&key)?;
        let finish_input = NativeCapture17UploadInput::Finish { key: borrowed_key };
        let mut finish = json!({
            "status":"completed", "operation_state":"completed",
            "result":{"transfer_id":key.transfer,"content":content},
            "extensions":{},
        });
        let result = UploadResult::Verified(verified);
        authenticate_reply(
            finish.as_object().ok_or_else(refused)?,
            finish_input,
            &result,
        )?;
        finish["result"]["content"]["hash"]["domain"] = json!("changed");
        assert!(
            authenticate_reply(
                finish.as_object().ok_or_else(refused)?,
                finish_input,
                &result
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn decimal_reply_values_require_exact_canonical_u64_text() {
        for value in [0, 1, 9, 10, 50, u64::MAX] {
            assert!(integer(Some(&json!(value.to_string())), U64::new(value)));
        }
        for text in ["", "+0", "00", "01", "-1", " 1", "18446744073709551616"] {
            assert!(!integer(Some(&json!(text)), U64::new(0)));
        }
        assert!(!integer(Some(&json!(0)), U64::new(0)));
        assert!(!integer(Some(&json!("1")), U64::new(2)));
    }
}
