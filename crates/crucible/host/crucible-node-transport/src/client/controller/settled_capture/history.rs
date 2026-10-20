//! Borrows every Capture/upload/confirmation partial as closed inert history.
//!
//! ```text
//! {schema, request_id, operation_id, body, request, prefix_frontier,
//!  auxiliary_uploads, arguments, unsigned_request, original, context, artifact,
//!  canonical, cut_present, terminal, decoded, roots, capture_frontier,
//!  confirmation, stage}
//! ```
//!
//! Deadlines are represented only by presence, never portable clock values.
//! Raw and typed responses remain independent even if they disagree. Capacity
//! and alias rows come from the actual owning walk, independently of this value.

use super::*;
use serde::ser::{SerializeSeq, SerializeStruct};

/// Borrows the actual once owner without decoding or granting Capture authority.
pub struct OriginalRestoredSettledCaptureData<'a> {
    original: &'a AssignedRestoredSettledCapture,
}

struct UploadData<'a>(&'a upload::AssignedAuxiliaryUpload);
struct OriginalData<'a>(&'a upload::AuxiliaryOriginal);
struct ConfirmationData<'a>(&'a AssignedConfirmation);
struct ResponseData<'a>(&'a ResponseBody);
struct UploadsData<'a>(&'a [Option<upload::AssignedAuxiliaryUpload>; 2]);
struct OriginalsData<'a>(&'a [upload::AuxiliaryOriginal]);
struct AuxiliaryBodyData<'a>(&'a RestoredSettledCaptureAuxiliaryBody);

impl CnpController {
    /// Borrows the same complete or partial Capture owner without live checks.
    ///
    /// The Source separately authenticates its original actor and ticket. This
    /// view stays available after failed correlation, IO, fencing or revocation.
    ///
    /// # Errors
    /// Refuses only a missing once owner. Serialization can refuse an unsupported
    /// independently decoded response family; it never drops the retained owner.
    pub fn original_restored_settled_capture_data(
        &self,
    ) -> Result<OriginalRestoredSettledCaptureData<'_>, ProviderError> {
        Ok(OriginalRestoredSettledCaptureData {
            original: self
                .original_restored_settled_capture
                .as_ref()
                .ok_or_else(refused)?,
        })
    }
}

impl OriginalRestoredSettledCaptureData<'_> {
    /// Borrows the exact signed request DATA, including a failed reservation.
    pub fn request_data(&self) -> &PacketRestoredSettledCaptureRequest {
        &self.original.request
    }

    /// Borrows the actual assigned Capture, if assignment initialized it.
    pub fn original_data(&self) -> Option<&Envelope> {
        self.original.original.as_ref()
    }

    /// Borrows the actual raw Capture terminal, including post-receive refusal.
    pub fn terminal_data(&self) -> Option<&Envelope> {
        self.original.terminal.as_ref()
    }

    /// Borrows its independent typed response without inferring raw correspondence.
    pub fn response_body_data(&self) -> Option<&ResponseBody> {
        self.original.decoded.as_deref()
    }

    /// Borrows the raw final Poll terminal, including a failed receipt check.
    pub fn confirmation_terminal_data(&self) -> Option<&Envelope> {
        self.original
            .confirmation
            .as_ref()
            .and_then(|value| value.terminal.as_ref())
    }

    /// Borrows the actual retained fourth receipt before additional Source checks.
    pub fn confirmation_receipt_data(
        &self,
    ) -> Option<&PacketRestoredSettledAfterConfirmationReceipt> {
        self.original
            .confirmation
            .as_ref()
            .and_then(|value| value.receipt.as_ref())
    }

    /// Reports completion only after the final same-owner transport checks.
    pub fn completed_frontier_data(&self) -> Option<U64> {
        if self.original.stage == Stage::Complete {
            self.original
                .confirmation
                .as_ref()
                .and_then(|value| value.frontier)
        } else {
            None
        }
    }
}

impl PreparedOriginalRestoredSettledCapture<'_> {
    /// Borrows the last completed ordinal original and independent typed reply.
    ///
    /// # Errors
    /// Refuses missing/partial ordinal custody. This DATA does not authenticate
    /// the Source MAC, native spent lease or whole Capture ticket.
    pub fn auxiliary_completed_pair_data(
        &self,
        ordinal: crate::reference_packet::service::restored_settled_capture::upload::PacketRestoredSettledCaptureUploadOrdinal,
    ) -> Result<(&Envelope, &Envelope, &ResponseBody), ProviderError> {
        use crate::reference_packet::service::restored_settled_capture::upload::PacketRestoredSettledCaptureUploadOrdinal;
        let ordinal = match ordinal {
            PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix => 0,
            PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject => 1,
        };
        let state = self
            .controller
            .original_restored_settled_capture
            .as_ref()
            .ok_or_else(refused)?;
        let last = state.auxiliary_uploads[ordinal]
            .as_ref()
            .and_then(|value| value.completed.last())
            .ok_or_else(refused)?;
        Ok((
            last.original.as_ref().ok_or_else(refused)?,
            last.terminal.as_ref().ok_or_else(refused)?,
            last.decoded.as_deref().ok_or_else(refused)?,
        ))
    }

    /// Borrows a transferred Capture object already present in actual custody.
    ///
    /// # Errors
    /// Refuses a reference outside this Capture's three actual typed results and
    /// retained fourth receipt, or absent/hash-inconsistent content. No fetch runs.
    pub fn transferred_object_data(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        let state = self
            .controller
            .original_restored_settled_capture
            .as_ref()
            .ok_or_else(refused)?;
        let capture = state
            .decoded
            .as_deref()
            .and_then(|value| match value.result.as_ref() {
                Some(MethodResult::Capture(capture)) => Some(capture),
                _ => None,
            });
        let known = capture.is_some_and(|value| {
            &value.capture_manifest == reference
                || &value.unchanged_cut_receipt == reference
                || value.owner_state_refs.contains(reference)
        }) || state
            .confirmation
            .as_ref()
            .and_then(|value| value.receipt.as_ref())
            .is_some_and(|value| &value.native_after_ref == reference);
        if !known {
            return Err(refused());
        }
        self.controller.custody.content().get(reference)
    }
}

impl Serialize for ResponseData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        crate::retained_metadata::historical_response_body_data(self.0)
            .map_err(|_| S::Error::custom("unsupported settled Capture typed history"))?
            .serialize(serializer)
    }
}

impl Serialize for OriginalRestoredSettledCaptureData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.original;
        let mut fields = serializer.serialize_struct("RestoredSettledCapture", 21)?;
        fields.serialize_field("schema", "source-private.restored-settled-capture-sdk/17")?;
        fields.serialize_field("request_id", &value.request_id)?;
        fields.serialize_field("operation_id", &value.operation_id)?;
        fields.serialize_field("body", &value.body)?;
        fields.serialize_field("request", &value.request)?;
        fields.serialize_field("prefix_frontier", &value.prefix_frontier)?;
        fields.serialize_field("auxiliary_uploads", &UploadsData(&value.auxiliary_uploads))?;
        fields.serialize_field(
            "maximum_auxiliary_originals",
            &value.maximum_auxiliary_originals,
        )?;
        fields.serialize_field("arguments", &value.arguments)?;
        fields.serialize_field("unsigned_request", &value.unsigned_request)?;
        fields.serialize_field("original", &value.original)?;
        fields.serialize_field("context", &value.context)?;
        fields.serialize_field("artifact", &value.artifact)?;
        fields.serialize_field("canonical", &value.canonical)?;
        fields.serialize_field("cut_present", &value.cut.is_some())?;
        fields.serialize_field("terminal", &value.terminal)?;
        fields.serialize_field("decoded", &value.decoded.as_deref().map(ResponseData))?;
        fields.serialize_field("roots", &value.roots)?;
        fields.serialize_field("capture_frontier", &value.capture_frontier)?;
        fields.serialize_field(
            "confirmation",
            &value.confirmation.as_ref().map(ConfirmationData),
        )?;
        fields.serialize_field(
            "stage",
            &match value.stage {
                Stage::Reserving => "reserving",
                Stage::Reserved => "reserved",
                Stage::Assigning => "assigning",
                Stage::Unsigned => "unsigned",
                Stage::Sealing => "sealing",
                Stage::Sealed => "sealed",
                Stage::Publishing => "publishing",
                Stage::Captured => "captured",
                Stage::Confirming => "confirming",
                Stage::Complete => "complete",
            },
        )?;
        fields.end()
    }
}

impl Serialize for UploadsData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(2))?;
        for value in self.0 {
            values.serialize_element(&value.as_ref().map(UploadData))?;
        }
        values.end()
    }
}

impl Serialize for OriginalsData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            values.serialize_element(&OriginalData(value))?;
        }
        values.end()
    }
}

impl Serialize for AuxiliaryBodyData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("CaptureAuxiliaryBody", 2)?;
        match self.0 {
            RestoredSettledCaptureAuxiliaryBody::Begin(value) => {
                fields.serialize_field("kind", "begin")?;
                fields.serialize_field("data", value)?;
            }
            RestoredSettledCaptureAuxiliaryBody::Chunk(value) => {
                fields.serialize_field("kind", "chunk")?;
                fields.serialize_field("data", value)?;
            }
            RestoredSettledCaptureAuxiliaryBody::Finish(value) => {
                fields.serialize_field("kind", "finish")?;
                fields.serialize_field("data", value)?;
            }
        }
        fields.end()
    }
}

impl Serialize for UploadData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let mut fields = serializer.serialize_struct("CaptureAuxiliaryUpload", 9)?;
        fields.serialize_field("request", &value.request)?;
        fields.serialize_field("context", &value.context)?;
        fields.serialize_field("artifact", &value.artifact)?;
        fields.serialize_field("pending", &value.pending.as_ref().map(OriginalData))?;
        fields.serialize_field("completed", &OriginalsData(&value.completed))?;
        fields.serialize_field("next_offset", &value.next_offset)?;
        fields.serialize_field("maximum_chunk", &value.maximum_chunk)?;
        fields.serialize_field("finished", &value.finished)?;
        fields.serialize_field("maximum_originals", &value.maximum_originals)?;
        fields.end()
    }
}

impl Serialize for OriginalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let mut fields = serializer.serialize_struct("CaptureAuxiliaryOriginal", 10)?;
        fields.serialize_field("request_id", &value.request_id)?;
        fields.serialize_field("body", &AuxiliaryBodyData(&value.body))?;
        fields.serialize_field("continuation", &value.continuation)?;
        fields.serialize_field("extension", &value.extension)?;
        fields.serialize_field("original", &value.original)?;
        fields.serialize_field("cut_present", &value.cut.is_some())?;
        fields.serialize_field("terminal", &value.terminal)?;
        fields.serialize_field("decoded", &value.decoded.as_deref().map(ResponseData))?;
        fields.serialize_field("frontier", &value.frontier)?;
        fields.serialize_field(
            "stage",
            &match value.stage {
                upload::AuxiliaryStage::Preparing => "preparing",
                upload::AuxiliaryStage::Unsigned => "unsigned",
                upload::AuxiliaryStage::Sealing => "sealing",
                upload::AuxiliaryStage::Assigned => "assigned",
                upload::AuxiliaryStage::Publishing => "publishing",
                upload::AuxiliaryStage::Complete => "complete",
            },
        )?;
        fields.end()
    }
}

impl Serialize for ConfirmationData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let mut fields = serializer.serialize_struct("CaptureConfirmation", 11)?;
        fields.serialize_field("request_id", &value.request_id)?;
        fields.serialize_field("request", &value.request)?;
        fields.serialize_field("extension", &value.extension)?;
        fields.serialize_field("original", &value.original)?;
        fields.serialize_field("cut_present", &value.cut.is_some())?;
        fields.serialize_field("terminal", &value.terminal)?;
        fields.serialize_field("decoded", &value.decoded.as_deref().map(ResponseData))?;
        fields.serialize_field("receipt", &value.receipt)?;
        fields.serialize_field("roots", &value.roots)?;
        fields.serialize_field("frontier", &value.frontier)?;
        fields.serialize_field(
            "stage",
            &match value.stage {
                ConfirmationStage::Preparing => "preparing",
                ConfirmationStage::Assigned => "assigned",
                ConfirmationStage::Publishing => "publishing",
                ConfirmationStage::Complete => "complete",
            },
        )?;
        fields.end()
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<UploadData<'static>>()
        + size_of::<OriginalData<'static>>()
        + size_of::<ConfirmationData<'static>>()
        + size_of::<ResponseData<'static>>()
        + size_of::<UploadsData<'static>>()
        + size_of::<OriginalsData<'static>>()
        + size_of::<AuxiliaryBodyData<'static>>()
        + size_of::<Option<UploadData<'static>>>()
        + size_of::<Option<OriginalData<'static>>>()
        + size_of::<Option<ConfirmationData<'static>>>()
        + size_of::<Option<ResponseData<'static>>>()
        + size_of::<&[upload::AuxiliaryOriginal]>()
        + size_of::<std::slice::Iter<'static, upload::AuxiliaryOriginal>>()
        + size_of::<std::slice::Iter<'static, Option<upload::AssignedAuxiliaryUpload>>>()
        + size_of::<
            std::iter::Flatten<std::slice::Iter<'static, Option<upload::AssignedAuxiliaryUpload>>>,
        >()
        + size_of::<Option<&upload::AuxiliaryOriginal>>()
        + size_of::<Option<&upload::AssignedAuxiliaryUpload>>()
        + size_of::<Option<&AssignedConfirmation>>()
        + size_of::<Option<&MethodResult>>()
        + size_of::<Option<&CaptureResult>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A partial DATA owner, never a live Source, Controller or native permit.
    fn partial() -> upload::AuxiliaryOriginal {
        let mut bytes = Vec::with_capacity(73);
        bytes.extend_from_slice(b"partial upload");
        upload::AuxiliaryOriginal {
            request_id: Id::new("capture-history-original").unwrap(),
            body: RestoredSettledCaptureAuxiliaryBody::Chunk(BlobChunkRequest {
                transfer_id: Id::new("capture-history-transfer").unwrap(),
                offset: U64::new(7),
                bytes: Bytes::new(bytes),
                extensions: Extensions::new(),
            }),
            continuation: None,
            extension: Some(serde_json::json!({"independent_raw": "retained"})),
            original: None,
            cut: None,
            terminal: None,
            decoded: Some(Box::new(ResponseBody {
                shape: ResponseShape::Error {
                    operation_state: OperationState::Unknown,
                    error: ErrorRecord {
                        code: "OUTCOME_UNKNOWN".into(),
                        message: "partial typed reply".into(),
                        effect: EffectCertainty::Unknown,
                        retryable: false,
                        details: Default::default(),
                    },
                    extensions: Extensions::new(),
                },
                result: Some(MethodResult::BlobChunk(BlobChunkResult {
                    transfer_id: Id::new("independent-typed-transfer").unwrap(),
                    next_offset: U64::new(19),
                })),
            })),
            frontier: None,
            stage: upload::AuxiliaryStage::Publishing,
        }
    }

    #[test]
    fn capture_upload_history_retains_raw_typed_and_pending_body_independently() {
        let value = partial();
        let encoded = serde_json::to_value(OriginalData(&value)).unwrap();
        assert_eq!(encoded["stage"], "publishing");
        assert_eq!(encoded["body"]["kind"], "chunk");
        assert_eq!(encoded["body"]["data"]["offset"], "7");
        assert_eq!(encoded["extension"]["independent_raw"], "retained");
        assert_eq!(encoded["decoded"]["shape"]["status"], "error");
        assert_eq!(encoded["decoded"]["result"]["kind"], "blob_chunk");
        assert_eq!(
            encoded["decoded"]["result"]["data"]["transfer_id"],
            "independent-typed-transfer"
        );
        assert!(encoded["original"].is_null());
        assert!(encoded["terminal"].is_null());
        assert_eq!(encoded["cut_present"], false);
    }
}

impl OriginalRestoredSettledCaptureData<'_> {
    /// Borrows the actual fourth Poll request context, including partial refusal.
    pub fn confirmation_request_data(
        &self,
    ) -> Option<&PacketRestoredSettledAfterConfirmationRequest> {
        self.original
            .confirmation
            .as_ref()
            .map(|value| &value.request)
    }

    /// Borrows its actual assigned fourth Poll original without reconstructing it.
    pub fn confirmation_original_data(&self) -> Option<&Envelope> {
        self.original
            .confirmation
            .as_ref()
            .and_then(|value| value.original.as_ref())
    }

    /// Borrows its independent typed Poll, even when later receipt checks failed.
    pub fn confirmation_response_body_data(&self) -> Option<&ResponseBody> {
        self.original
            .confirmation
            .as_ref()
            .and_then(|value| value.decoded.as_deref())
    }
}

impl PreparedOriginalRestoredSettledCapture<'_> {
    /// Borrows all partial custody while retaining the same exclusive marker.
    ///
    /// # Errors
    /// Refuses a missing once owner without reconstructing any historical state.
    pub fn partial_data(&self) -> Result<OriginalRestoredSettledCaptureData<'_>, ProviderError> {
        self.controller.original_restored_settled_capture_data()
    }
}
