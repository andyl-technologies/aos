//! Quotes the completed Source reader before constructing its owning DOM.
//!
//! Byte-vector banks are walked separately from typed records. Charging every
//! byte as a large enum element would make valid bounded histories impossible
//! to decode. These numbers are storage DATA; all signed, native and parent
//! correspondence checks still belong to the completed reader.

use super::*;
use crate::node_contract::NodeRuntime;
use crucible_node_transport::protocol_snapshot::{
    borrowed_json::{BorrowedJsonFields as Fields, counter_scratch_data as fields_scratch},
    current_controller17::{
        ValidatedControllerSettledHistory17, ValidatedHistoricalRestoredSettledCapture17,
        historical_restoration_association17_counter_scratch_data,
        historical_restoration_association17_selected_counter_scratch_data,
        historical_restoration_association17_validation_transient_for_controller_data,
        historical_restored_settled_capture17_counter_scratch_data,
        historical_restored_settled_capture17_selected_counter_scratch_data,
        historical_restored_settled_capture17_selected_retained_construction_bytes_data,
        historical_restored_settled_capture17_selected_validation_transient_bytes_data,
        historical_restored_suffix_pair_counter_scratch_data,
        historical_restored_suffix_pair_validation_transient_bytes_data,
    },
    restored_journal17::PacketRestoredSettledSemantic17Plan,
    restored_settled17::{
        RestoredSettledSourceHistory17AuthGeometryData,
        restored_settled_native17_counter_scratch_data,
        source_history17_authentication_counter_scratch_data,
    },
};
use std::mem::size_of;

#[path = "construction/attempt.rs"]
mod attempt;
pub(crate) use attempt::OriginalSourceRestoredSettled17DecodeAttempt;

#[path = "construction/layouts.rs"]
mod layouts;
use layouts::Family;

#[path = "construction/prelude.rs"]
mod prelude;

/// Describes the independently summed new Source decode owners and temporaries.
pub(crate) struct OriginalSourceRestoredSettled17DecodeConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalSourceRestoredSettled17DecodeConstructionData {
    pub(crate) fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    pub(crate) fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    pub(crate) fn declared_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
}

impl OriginalSourceRestoredSettled17Read {
    /// Quotes complete raw, typed, canonical and verifier work without allocating.
    ///
    /// The caller admits this row together with its existing archive, all prior
    /// decoded owners and the defining fixed counter before invoking this walk.
    /// It retains raw literal/DOM owners before calling the completed reader.
    ///
    /// # Errors
    /// Refuses unsupported root/attempt framing, malformed byte banks, overlong
    /// banks or histories, checked layout overflow and the independent ceiling.
    pub(crate) fn completed_decode_construction_data(
        semantic_reference: &ContentRef,
        node_reference: &ContentRef,
        semantic: &[u8],
        prefix: &[u8],
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        sdk_capture: &ValidatedHistoricalRestoredSettledCapture17,
        maximum: usize,
    ) -> Result<OriginalSourceRestoredSettled17DecodeConstructionData, RuntimeError> {
        if semantic.is_empty()
            || prefix.is_empty()
            || semantic.len() > maximum
            || prefix.len() > maximum
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let plan =
            PacketRestoredSettledSemantic17Plan::validate(semantic, maximum).map_err(invalid)?;
        let mut quote = Quote {
            retained: 0,
            transient: 0,
            maximum,
        };
        // Raw semantic is retained. Prefix and all cloned/expected comparison
        // DOMs coexist with it; summing all selected temporary fields is a
        // conservative bound even where a defining function drops one earlier.
        quote.raw(semantic, true)?;
        // The attempt and successful output retain independently censused Rc
        // loans. No shared-backing refund is used by their owning rows.
        let (_, attempt_dom, attempt_canonical) =
            NodeRuntime::capture_selected_json_decode_axes_data(semantic, 1, 1, maximum)?;
        quote.retained(attempt_dom)?;
        quote.retained(attempt_canonical)?;
        quote.retained(NodeRuntime::capture_shared_allocation_storage::<Value>())?;
        quote.retained(size_of::<OriginalSourceRestoredSettled17DecodeAttempt>())?;
        quote.raw(prefix, false)?;
        // Public Source reference and inventory checks create a sequential
        // HashRef independently of their canonical input bank. The inventory
        // domain is the widest of the Source's fixed public hash domains.
        quote.transient("blake3-256".len() + "source-owned.packet-inventory.v1".len() + 64)?;
        quote.transient_typed(
            plan.ancestry_bytes(),
            size_of::<crucible_node_transport::protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17>(),
        )?;
        quote.prefix_reference(prefix)?;
        let mut fields = Fields::object(plan.source_bytes()).map_err(invalid)?;
        let capture = fields.named("capture").map_err(invalid)?;
        let current = fields.named("current_observations").map_err(invalid)?;
        let first = fields.named("first_observation").map_err(invalid)?;
        let inherited = fields.named("inherited").map_err(invalid)?;
        let input = fields.named("input_history").map_err(invalid)?;
        let installation = fields.named("installation").map_err(invalid)?;
        let limits = fields.named("limits").map_err(invalid)?;
        let once = fields.named("once").map_err(invalid)?;
        let producer = fields.named("producer").map_err(invalid)?;
        let schema = fields.named("schema").map_err(invalid)?;
        let world = fields.named("world").map_err(invalid)?;
        fields.finish().map_err(invalid)?;
        if schema != br#""source-private.source-restored-settled-state/17""# || input != b"null" {
            return Err(RuntimeError::UnsupportedFacet);
        }
        // Recurring old16 and Input remain closed at this exact decoder.
        quote.typed(current, Family::Scalar.element_layout_data())?;
        quote.typed(capture, Family::Capture.element_layout_data())?;
        quote.typed(inherited, size_of::<ContentRef>())?;
        quote.typed(installation, Family::Installation.element_layout_data())?;
        quote.typed(limits, size_of::<OriginalSourceRestoredLimits17>())?;
        quote.once(once)?;
        quote.typed(world, Family::World.element_layout_data())?;
        quote.first(first)?;
        quote.sdk_first(controller)?;
        quote.producer(producer)?;
        // These defining quotes cover the independent Controller-derived SDK
        // owners. Producer suffix pairs are instead priced from their exact
        // Source literal subtrees in producer(), including all four simultaneous
        // lifecycle pairs and each separately verified upload.
        // Capture housekeeping retains a SECOND independently decoded SDK
        // Capture owner. Its R cannot be funded by the earlier collector copy
        // or by the transient validator row below.
        quote.retained(
            historical_restored_settled_capture17_selected_retained_construction_bytes_data(
                controller, maximum,
            )
            .map_err(invalid)?,
        )?;
        quote.transient(
            historical_restoration_association17_validation_transient_for_controller_data(
                controller, maximum,
            )
            .map_err(invalid)?,
        )?;
        quote.transient(
            historical_restored_settled_capture17_selected_validation_transient_bytes_data(
                controller, maximum,
            )
            .map_err(invalid)?,
        )?;
        // Native-private contexts and cached proof bodies are priced by their
        // defining owner. Public supplied Source model reparses and malformed
        // formatter work remain independently funded by the exact spans above.
        let native_geometry = native
            .source_history17_authentication_geometry_data(controller, sdk_capture, maximum)
            .map_err(invalid)?;
        quote.transient(native_geometry.maximum_simultaneous_transient_bytes_data())?;
        // The public prewalk getter is admitted before entering this quote.
        // Preserve any additional actual shape-dependent fixed controls too.
        let native_scratch = native_geometry.declared_counter_scratch_bytes_data();
        // Typed public original declaration, profile, capability and guarantee
        // bodies are separately re-encoded by the installation correspondence
        // checker. Their aggregate encoded extent is bounded by this exact
        // installation subtree; count all four projected DOM/canonical owners.
        for _ in 0..4 {
            quote.raw(installation, false)?;
        }
        quote.retained(size_of::<Self>())?;
        quote.retained(NodeRuntime::capture_shared_allocation_storage::<Value>())?;
        // Actual full-reference clone backing remains independent of raw DOM.
        quote.retained(NodeRuntime::capture_reference_storage(semantic_reference)?)?;
        quote.retained(NodeRuntime::capture_reference_storage(node_reference)?)?;
        let scratch = Self::completed_decode_counter_scratch_data()
            .checked_add(native_scratch)
            .ok_or(RuntimeError::ResourceLimit)?;
        quote
            .total()?
            .checked_add(scratch)
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(OriginalSourceRestoredSettled17DecodeConstructionData {
            retained: quote.retained,
            transient: quote.transient,
            scratch,
        })
    }

    /// Names all defining nonallocating preflight and reader control layouts.
    pub(crate) fn completed_decode_counter_scratch_data() -> usize {
        Self::counter_scratch_data()
            + OriginalSourceRestoredSettled17DecodeAttempt::counter_scratch_data()
            + OriginalSourceRestoredOnce17Read::completed_decode_counter_scratch_data()
            + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + fields_scratch()
            + size_of::<PacketRestoredSettledSemantic17Plan<'static>>()
            + size_of::<Result<PacketRestoredSettledSemantic17Plan<'static>, crucible_node_transport::ProviderError>>()
            + Family::counter_scratch_data()
            + size_of::<[Fields<'static>; 8]>()
            + size_of::<crucible_node_format::HashRef>()
            + 4 * (size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
                + size_of::<(&Value, usize, usize)>())
            + size_of::<[&'static str; 35]>()
            + size_of::<OriginalSourceRestoredSettled17DecodeConstructionData>()
            + size_of::<Quote>() * 2
            + size_of::<ContentRef>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<([u8; 64], usize)>()
            + size_of::<crucible_node_transport::protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17>()
            + size_of::<Option<&[u8]>>()
            + size_of::<Result<OriginalSourceRestoredSettled17DecodeConstructionData, RuntimeError>>(
            )
            + historical_restoration_association17_counter_scratch_data()
            + historical_restoration_association17_selected_counter_scratch_data()
            + historical_restored_settled_capture17_counter_scratch_data()
            + historical_restored_settled_capture17_selected_counter_scratch_data()
            + historical_restored_suffix_pair_counter_scratch_data()
            + restored_settled_native17_counter_scratch_data()
            + source_history17_authentication_counter_scratch_data()
            + size_of::<RestoredSettledSourceHistory17AuthGeometryData>()
            + size_of::<Result<RestoredSettledSourceHistory17AuthGeometryData, crucible_node_transport::ProviderError>>()
    }
}

struct Quote {
    retained: usize,
    transient: usize,
    maximum: usize,
}

impl Quote {
    fn retained(&mut self, amount: usize) -> Result<(), RuntimeError> {
        self.retained = self
            .retained
            .checked_add(amount)
            .filter(|n| *n <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn transient(&mut self, amount: usize) -> Result<(), RuntimeError> {
        self.transient = self
            .transient
            .checked_add(amount)
            .filter(|n| *n <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn total(&self) -> Result<usize, RuntimeError> {
        self.retained
            .checked_add(self.transient)
            .ok_or(RuntimeError::ResourceLimit)
    }

    fn raw(&mut self, bytes: &[u8], retained: bool) -> Result<(), RuntimeError> {
        let (_, dom, canonical) =
            NodeRuntime::capture_selected_json_decode_axes_data(bytes, 1, 1, self.maximum)?;
        if retained {
            self.retained(dom)?;
        } else {
            self.transient(dom)?;
        }
        self.transient(canonical)
    }

    fn typed(&mut self, bytes: &[u8], slot: usize) -> Result<(), RuntimeError> {
        // The selected explicit family roster includes nested Vec and map
        // values. The opaque output's inline size alone is not the bound.
        // Eleven key/value entries fit in each defining BTree node.
        let map = NodeRuntime::capture_map_node_storage::<String, Value>()
            .checked_add(slot.checked_mul(11).ok_or(RuntimeError::ResourceLimit)?)
            .ok_or(RuntimeError::ResourceLimit)?;
        let (typed, dom, canonical) = NodeRuntime::capture_selected_json_decode_axes_data(
            bytes,
            slot.max(size_of::<Value>()),
            map,
            self.maximum,
        )?;
        self.retained(typed)?;
        // The typed roundtrip and serde tagged-content buffering coexist
        // with the retained result. Native model revalidation has its own
        // separately named row below, including its boxed root.
        self.transient(typed)?;
        // `read` owns an independent input clone and expected typed projection.
        self.transient(dom.checked_mul(2).ok_or(RuntimeError::ResourceLimit)?)?;
        self.transient(canonical)?;
        // Custom Bytes serializes through an allocated base64 String even
        // inside serialized_credit. Its spelling fits the exact supplied typed
        // subtree (raw escapes only enlarge that span); admit geometric growth
        // independently of the subsequent DOM/canonical pools.
        let formatter = bytes
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .ok_or(RuntimeError::ResourceLimit)?;
        self.transient(formatter)
    }

    fn transient_typed(&mut self, bytes: &[u8], slot: usize) -> Result<(), RuntimeError> {
        let mut temporary = Self {
            retained: 0,
            transient: 0,
            maximum: self.maximum,
        };
        temporary.typed(bytes, slot)?;
        // This parsed DTO is local validation work. It never becomes a member
        // of the opaque completed Source or a permanent retained allocation.
        self.transient(temporary.total()?)
    }

    fn prefix_reference(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let mut prefix = Fields::object(bytes).map_err(invalid)?;
        let checkpoint = prefix.named("coordinator_checkpoint").map_err(invalid)?;
        prefix.named("history").map_err(invalid)?;
        if prefix.named("schema").map_err(invalid)?
            != br#""source-private.source-restored-settled-capture-prefix/17""#
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        prefix.finish().map_err(invalid)?;
        let mut checkpoint = Fields::object(checkpoint).map_err(invalid)?;
        checkpoint.named("body").map_err(invalid)?;
        self.transient_typed(
            checkpoint.named("reference").map_err(invalid)?,
            size_of::<ContentRef>(),
        )?;
        checkpoint.finish().map_err(invalid)
    }

    fn native_model_revalidation(
        &mut self,
        record: &[u8],
        underlying: &[u8],
    ) -> Result<(), RuntimeError> {
        let slot = Family::First.element_layout_data();
        let map = NodeRuntime::capture_map_node_storage::<String, Value>()
            .checked_add(slot.checked_mul(11).ok_or(RuntimeError::ResourceLimit)?)
            .ok_or(RuntimeError::ResourceLimit)?;
        let (typed, dom, underlying_canonical) =
            NodeRuntime::capture_selected_json_decode_axes_data(
                underlying,
                slot,
                map,
                self.maximum,
            )?;
        let (_, _, record_canonical) =
            NodeRuntime::capture_selected_json_decode_axes_data(record, 1, 1, self.maximum)?;

        // Native verification keeps the Source model, a newly decoded model
        // and its Box allocation independently. Both DOM decoding and serde's
        // tagged-content buffering may coexist with that new typed backing.
        self.transient(typed)?;
        self.transient(slot)?;
        self.transient(dom.checked_mul(2).ok_or(RuntimeError::ResourceLimit)?)?;

        // record_bytes and underlying_bytes remain live while decode_record
        // checks another canonical bank, then the verified model is encoded
        // once more for equality. Both stages fit record + two underlying banks.
        self.transient(record_canonical)?;
        self.transient(
            underlying_canonical
                .checked_mul(2)
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        self.transient(
            underlying
                .len()
                .checked_mul(4)
                .and_then(|n| n.checked_add(8))
                .ok_or(RuntimeError::ResourceLimit)?,
        )
    }

    fn bank(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let mut array = Fields::array(bytes).map_err(invalid)?;
        let mut count = 0usize;
        while let Some(value) = array.next_value().map_err(invalid)? {
            let text = std::str::from_utf8(value).map_err(invalid)?;
            text.parse::<u8>().map_err(invalid)?;
            count = count
                .checked_add(1)
                .filter(|n| *n <= self.maximum)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        array.finish().map_err(invalid)?;
        // Conservative geometric Vec growth plus its retained fixed header.
        let backing = count
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .ok_or(RuntimeError::ResourceLimit)?;
        self.retained(backing)?;
        self.transient(size_of::<Vec<u8>>())
    }

    fn four_banks(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let mut banks = Fields::array(bytes).map_err(invalid)?;
        for _ in 0..4 {
            self.bank(
                banks
                    .next_value()
                    .map_err(invalid)?
                    .ok_or(RuntimeError::InvalidReceipt)?,
            )?;
        }
        banks.finish().map_err(invalid)
    }

    fn payload(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let mut fields = Fields::object(bytes).map_err(invalid)?;
        self.bank(fields.named("bytes").map_err(invalid)?)?;
        self.typed(
            fields.named("reference").map_err(invalid)?,
            size_of::<ContentRef>(),
        )?;
        fields.finish().map_err(invalid)
    }

    fn first(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let mut fields = Fields::object(bytes).map_err(invalid)?;
        self.four_banks(fields.named("banks").map_err(invalid)?)?;
        let mut native_record = None;
        for name in [
            "binding",
            "record",
            "reserved",
            "scheduling",
            "schema",
            "underlying",
        ] {
            let value = fields.named(name).map_err(invalid)?;
            self.typed(value, Family::First.element_layout_data())?;
            if name == "record" {
                native_record = Some(value);
            } else if name == "underlying" {
                self.native_model_revalidation(
                    native_record.ok_or(RuntimeError::InvalidReceipt)?,
                    value,
                )?;
            }
        }
        // SDKFirst retains independent typed request/original/terminal/response
        // owners authenticated to these four exact Source values.
        self.typed(
            fields.named("values").map_err(invalid)?,
            Family::First.element_layout_data(),
        )?;
        self.typed(
            fields.named("verified").map_err(invalid)?,
            size_of::<bool>(),
        )?;
        fields.finish().map_err(invalid)
    }

    fn sdk_first(
        &mut self,
        controller: &ValidatedControllerSettledHistory17,
    ) -> Result<(), RuntimeError> {
        // The actual SDKFirst parser runs before Source values are compared.
        // An unequal smaller Source tuple cannot fund a larger Controller tuple
        // on the refusal path. Select the genuine immutable original spans.
        let root = controller.parts_data().map_err(invalid)?;
        let observation = root
            .get("observation")
            .and_then(Value::as_array)
            .filter(|row| row.len() == 13)
            .ok_or(RuntimeError::InvalidReceipt)?;
        let request_id = observation[4]
            .get("request_id")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::InvalidReceipt)?;
        let custody = root
            .get("custody")
            .and_then(Value::as_array)
            .filter(|row| row.len() == 6)
            .ok_or(RuntimeError::InvalidReceipt)?;
        let identity = custody[3]
            .get(request_id)
            .and_then(|entry| entry.get("identity"))
            .ok_or(RuntimeError::InvalidReceipt)?;
        self.transient(size_of::<crucible_node_format::HashRef>())?;
        self.reference_copy(identity, 0)?;
        // First-observation membership checks can decode a different dictionary
        // fullref before rejecting equality. Price the actual largest member,
        // rather than assuming the supplied Source's reference already matches.
        let wrapper = custody[5]
            .as_array()
            .filter(|row| row.len() == 4)
            .ok_or(RuntimeError::InvalidReceipt)?;
        let content = wrapper[1]
            .as_array()
            .filter(|row| row.len() == 7)
            .ok_or(RuntimeError::InvalidReceipt)?;
        let members = content[6].as_array().ok_or(RuntimeError::InvalidReceipt)?;
        let mut dictionary_peak = 0usize;
        for member in members {
            let member = member
                .as_array()
                .filter(|row| row.len() == 5)
                .ok_or(RuntimeError::InvalidReceipt)?;
            let mut temporary = Self {
                retained: 0,
                transient: 0,
                maximum: self.maximum,
            };
            temporary.transient(size_of::<ContentRef>())?;
            temporary.reference_copy(&member[1], 0)?;
            dictionary_peak = dictionary_peak.max(temporary.transient);
        }
        self.transient(dictionary_peak)?;
        self.sdk_first_literal(controller.original_bytes_data())
    }

    fn reference_copy(&mut self, value: &Value, depth: usize) -> Result<(), RuntimeError> {
        // The verified Controller owns closed HashRef/ContentRef records. The
        // SDK clones their Value before typed decoding; no new DOM is built by
        // this counter and no encoded-length guess substitutes for its fields.
        if depth > 3 {
            return Err(RuntimeError::InvalidReceipt);
        }
        match value {
            Value::String(text) => self.transient(
                text.len()
                    .checked_mul(4)
                    .and_then(|n| n.checked_add(8))
                    .ok_or(RuntimeError::ResourceLimit)?,
            ),
            Value::Object(fields) => {
                self.transient(
                    NodeRuntime::capture_map_node_storage::<String, Value>()
                        .checked_mul(fields.len())
                        .ok_or(RuntimeError::ResourceLimit)?,
                )?;
                for (name, value) in fields {
                    self.transient(
                        name.len()
                            .checked_mul(4)
                            .and_then(|n| n.checked_add(8))
                            .ok_or(RuntimeError::ResourceLimit)?,
                    )?;
                    self.reference_copy(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
            Value::Array(_) => Err(RuntimeError::InvalidReceipt),
        }
    }

    fn sdk_first_literal(&mut self, literal: &[u8]) -> Result<(), RuntimeError> {
        let mut fields = Fields::object(literal).map_err(invalid)?;
        for name in [
            "ack_admit",
            "activation",
            "budget_nanoseconds",
            "budget_seconds",
            "capture",
            "complete_restore",
            "custody",
            "execution_owner",
            "fenced",
            "node",
        ] {
            let value = fields.named(name).map_err(invalid)?;
            if name == "execution_owner" || name == "node" {
                self.transient_typed(value, size_of::<crucible_node_format::Id>())?;
            }
        }
        let mut observation =
            Fields::array(fields.named("observation").map_err(invalid)?).map_err(invalid)?;
        for index in 0..13 {
            let value = observation
                .next_value()
                .map_err(invalid)?
                .ok_or(RuntimeError::InvalidReceipt)?;
            match index {
                // These four independently typed owners survive in SDKFirst.
                2 | 4 | 9 | 10 => self.typed(value, Family::First.element_layout_data())?,
                // ObserveRequest is temporary but can precede any equality check.
                1 => self.transient_typed(value, Family::First.element_layout_data())?,
                12 => self.transient_typed(value, size_of::<U64>())?,
                _ => {}
            }
        }
        observation.finish().map_err(invalid)
    }

    fn once(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let mut fields = Fields::object(bytes).map_err(invalid)?;
        for name in [
            "activation",
            "association",
            "first_observation",
            "outer",
            "restore",
            "suffix",
            "transfer",
        ] {
            let value = fields.named(name).map_err(invalid)?;
            if name == "outer" {
                self.header(value)?;
            } else {
                self.typed(
                    value,
                    OriginalSourceRestoredOnce17Read::completed_decode_element_layout_data(),
                )?;
            }
        }
        fields.finish().map_err(invalid)
    }

    fn header(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let mut fields = Fields::object(bytes).map_err(invalid)?;
        let mut names = [
            "schema",
            "creator_role",
            "model",
            "ack_birth_attempted",
            "restored_suffix_attempted",
            "registry_retention_attempted",
            "registry_retention_failed",
            "complete_bytes_launch_reserved",
            "ack_emitter_selection",
            "ack_codec_metadata_extent",
            "native_ack_codec_metadata_extent",
            "ack_birth_input_banks",
            "ack_birth_input_banks_capacities",
            "complete_restore_selection",
            "restore_input_emitter_selection",
            "protocol_metadata_limits",
            "capture_allocation_selection",
            "fresh_restore_allocation_selection",
            "coordinator_policy17",
        ];
        names.sort_unstable();
        for name in names {
            let value = fields.named(name).map_err(invalid)?;
            if name != "ack_birth_input_banks" && name != "ack_birth_input_banks_capacities" {
                self.typed(
                    value,
                    OriginalSourceRestoredOnce17Read::completed_decode_element_layout_data(),
                )?;
            }
            // Header's bank/capacity checks only borrow the retained raw DOM;
            // they construct no typed Vec or capacity-controlled live bank.
        }
        fields.finish().map_err(invalid)
    }

    fn producer_checkpoint_boxes(&mut self, attempts: usize) -> Result<(), RuntimeError> {
        let root =
            size_of::<crucible_node_transport::reference_packet::control::PacketNativeRecord>();
        if attempts > 0 {
            // The final checkpoint moves an already decoded model into its own
            // Box. Its allocation is separate from the typed field's children.
            self.retained(root)?;
        }
        if attempts > 1 {
            // Assignment constructs the new Box before dropping the preceding
            // checkpoint. Both roots overlap even though all children move.
            self.transient(root)?;
        }
        Ok(())
    }

    fn suffix_pair(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.transient(
            historical_restored_suffix_pair_validation_transient_bytes_data(bytes.len())
                .map_err(invalid)?,
        )
    }

    fn producer(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes == b"null" {
            return Ok(());
        }
        let mut fields = Fields::object(bytes).map_err(invalid)?;
        let mut attempts =
            Fields::array(fields.named("attempts").map_err(invalid)?).map_err(invalid)?;
        let mut count = 0usize;
        while let Some(attempt) = attempts.next_value().map_err(invalid)? {
            count = count
                .checked_add(1)
                .filter(|n| *n <= 4096)
                .ok_or(RuntimeError::ResourceLimit)?;
            let mut fields = Fields::object(attempt).map_err(invalid)?;
            let mut names = super::super::producer_fields::ATTEMPT_FIELDS;
            names.sort_unstable();
            for name in names {
                let value = fields.named(name).map_err(invalid)?;
                match name {
                    "record_canonical" => self.four_banks(value)?,
                    "report_bytes" => self.bank(value)?,
                    "authorization" | "consumption" => self.payload(value)?,
                    "record_values" | "report_value" | "consumption_value" => {
                        self.raw(value, false)?
                    }
                    "slot" | "previous" | "signature" | "stage" => {
                        self.typed(value, size_of::<Value>())?
                    }
                    "begin" | "poll" | "retire" | "observe" => {
                        self.typed(value, Family::Producer.element_layout_data())?;
                        self.suffix_pair(value)?;
                    }
                    "uploads" => {
                        self.typed(value, Family::Producer.element_layout_data())?;
                        let mut uploads = Fields::array(value).map_err(invalid)?;
                        while let Some(pair) = uploads.next_value().map_err(invalid)? {
                            self.suffix_pair(pair)?;
                        }
                        uploads.finish().map_err(invalid)?;
                    }
                    _ => self.typed(value, Family::Producer.element_layout_data())?,
                }
            }
            fields.finish().map_err(invalid)?;
        }
        attempts.finish().map_err(invalid)?;
        self.producer_checkpoint_boxes(count)?;
        fields.named("failed").map_err(invalid)?;
        fields.named("schema").map_err(invalid)?;
        fields.finish().map_err(invalid)
    }
}

fn invalid(_: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::InvalidReceipt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_first_tuple_is_priced_before_later_source_equality() {
        fn controller_prefix(payload: &str) -> Vec<u8> {
            let mut root = serde_json::Map::new();
            for name in [
                "ack_admit",
                "activation",
                "budget_nanoseconds",
                "budget_seconds",
                "capture",
                "complete_restore",
                "custody",
                "execution_owner",
                "fenced",
                "node",
            ] {
                root.insert(name.to_owned(), Value::Null);
            }
            let mut first = vec![Value::Null; 13];
            first[4] = serde_json::json!({"body":payload});
            root.insert("observation".to_owned(), Value::Array(first));
            canonical::canonical_json(&Value::Object(root)).unwrap()
        }
        let mut small = Quote {
            retained: 0,
            transient: 0,
            maximum: usize::MAX,
        };
        small.sdk_first_literal(&controller_prefix("x")).unwrap();
        let mut large = Quote {
            retained: 0,
            transient: 0,
            maximum: usize::MAX,
        };
        large
            .sdk_first_literal(&controller_prefix(&"x".repeat(4096)))
            .unwrap();

        assert!(large.retained > small.retained);
        assert!(large.transient > small.transient);
        let mut short = Quote {
            retained: 0,
            transient: 0,
            maximum: small.total().unwrap(),
        };
        assert!(
            short
                .sdk_first_literal(&controller_prefix(&"x".repeat(4096)))
                .is_err()
        );
    }

    #[test]
    fn moved_producer_checkpoint_boxes_preserve_the_overlap_peak() {
        let root =
            size_of::<crucible_node_transport::reference_packet::control::PacketNativeRecord>();
        for (attempts, retained, transient) in [(0, 0, 0), (1, root, 0), (2, root, root)] {
            let mut quote = Quote {
                retained: 0,
                transient: 0,
                maximum: usize::MAX,
            };
            quote.producer_checkpoint_boxes(attempts).unwrap();
            assert_eq!((quote.retained, quote.transient), (retained, transient));
        }
    }

    #[test]
    fn native_public_model_work_is_an_independent_transient_row() {
        let record = br#"{"native_record":"proof"}"#;
        let underlying = br#"{"kind":"producer","value":{"pending":[]}}"#;
        let mut quote = Quote {
            retained: 0,
            transient: 0,
            maximum: usize::MAX,
        };
        quote.native_model_revalidation(record, underlying).unwrap();

        assert_eq!(quote.retained, 0);
        let complete = quote.transient;
        assert!(complete > Family::First.element_layout_data());
        let mut short = Quote {
            retained: 0,
            transient: 0,
            maximum: complete - 1,
        };
        assert!(short.native_model_revalidation(record, underlying).is_err());
        assert!(short.transient < complete);
        assert_eq!(record, br#"{"native_record":"proof"}"#);
    }

    #[test]
    fn byte_banks_charge_byte_growth_and_preserve_borrowed_inputs() {
        let bytes = b"[0,255,12,3]";
        let mut quote = Quote {
            retained: 0,
            transient: 0,
            maximum: 4096,
        };
        quote.bank(bytes).unwrap();
        assert_eq!(quote.retained, 24);
        assert_eq!(bytes, b"[0,255,12,3]");
        assert!(quote.bank(b"[256]").is_err());
        assert!(quote.bank(b"[1.0]").is_err());
    }

    #[test]
    fn bank_roster_and_independent_bounds_are_not_renewed() {
        let mut quote = Quote {
            retained: 0,
            transient: 0,
            maximum: 24,
        };
        quote.bank(b"[1,2,3,4]").unwrap();
        assert!(quote.bank(b"[0]").is_err());
        let mut quote = Quote {
            retained: 0,
            transient: 0,
            maximum: 4096,
        };
        assert!(quote.four_banks(b"[[1],[2],[3]]").is_err());
        assert!(quote.four_banks(b"[[1],[2],[3],[4],[5]]").is_err());
    }
}
