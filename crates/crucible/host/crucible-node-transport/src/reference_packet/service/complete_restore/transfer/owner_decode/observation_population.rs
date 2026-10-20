//! Counts retained output geometry before constructing scheduling observations.
//!
//! The same selected outer14/full15 owner and Control correspondence is checked
//! first. This DATA counts actual initialized model outputs and their string or
//! byte children without decoding a model or granting observation permission.

use super::*;
use crate::protocol_snapshot::owned11::{
    OriginalOwned11Fields as Fields, original_owned11_plain_string as plain_string,
    original_owned11_unsigned as unsigned,
};

/// Bounds model-derived children of a future independently owned observation.
///
/// Target endpoint, owner, bound, proof-reference and Core publication layouts
/// are independent caller terms. These numbers grant no construction right.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketCompleteRestoreModelOutputPopulationData {
    initialized_outputs: usize,
    publication_slots: usize,
    owned_string_payload_backing: usize,
}

impl PacketCompleteRestoreModelOutputPopulationData {
    /// Counts actual initialized entries in the captured model's output array.
    pub fn initialized_outputs_data(&self) -> usize {
        self.initialized_outputs
    }

    /// Bounds publication-vector backing for fallible collection and cloning.
    ///
    /// A nonempty fallible iterator can grow from the four-element minimum;
    /// twice its initialized length covers later geometric growth. This does
    /// not assume the model's declared spare capacity equals clone capacity.
    pub fn publication_slots_data(&self) -> usize {
        self.publication_slots
    }

    /// Bounds copied event-ID and payload children by actual model strings.
    ///
    /// The existing scanner counts initialized string growth and bytes, including
    /// unrelated model fields. Decoded payload bytes cannot exceed their encoded
    /// string's initialized extent. No container/root/endpoint/layout is included.
    pub fn owned_string_payload_backing_bytes_data(&self) -> usize {
        self.owned_string_payload_backing
    }
}

/// Counts model-derived observation children from the same selected raw inputs.
///
/// The Source admits this defining scratch before entry and independently adds
/// all actual Core publication, causal-parent, endpoint, owner, bound and proof
/// layouts. Source generation and each Node clone require separate copies of
/// those terms; the existing native/SDK evidence budget cannot pay for them.
/// Complete native model/history validation remains required before generation.
///
/// # Errors
/// Refuses invalid selected owner/Control correspondence, a missing or duplicate
/// model/capacity/output field, malformed raw geometry, initialized output count
/// above its declared capacity, arithmetic overflow or the existing input bound.
pub fn complete_restore_selected_model_output_population_data(
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
) -> Result<PacketCompleteRestoreModelOutputPopulationData, ProviderError> {
    // Reuse the genuine outer14/full15 constructor recipe, including exact
    // embedded Control equality and the unchanged requested/input ceilings.
    complete_restore_invocation_owner_construction_storage_data(inputs)?;
    population_from_control(inputs.control, inputs.maximum_input_bytes)
}

fn field<'a>(input: &'a [u8], wanted: &str) -> Result<&'a [u8], ProviderError> {
    let mut fields = Fields::object(input)?;
    let mut found = None;
    while let Some((key, value)) = fields.pair()? {
        if plain_string(key)? == wanted && found.replace(value).is_some() {
            return Err(exhausted());
        }
    }
    fields.finish()?;
    found.ok_or_else(exhausted)
}

fn output_capacity(model: &[u8]) -> Result<usize, ProviderError> {
    let mut capacities = Fields::object(field(model, "capacities")?)?;
    let mut seen = [false; 6];
    let mut outputs = None;
    while let Some((key, value)) = capacities.pair()? {
        let index = match plain_string(key)? {
            "events" => 0,
            "reactions" => 1,
            "delivered_inputs" => 2,
            "publications" => 3,
            "outputs" => 4,
            "stages" => 5,
            _ => return Err(exhausted()),
        };
        if std::mem::replace(&mut seen[index], true) {
            return Err(exhausted());
        }
        let count = usize::try_from(unsigned(value)?).map_err(|_| exhausted())?;
        if index == 4 {
            outputs = Some(count);
        }
    }
    capacities.finish()?;
    for present in seen {
        if !present {
            return Err(exhausted());
        }
    }
    outputs.ok_or_else(exhausted)
}

fn population_from_control(
    control: &[u8],
    maximum: usize,
) -> Result<PacketCompleteRestoreModelOutputPopulationData, ProviderError> {
    if control.is_empty() || control.len() > maximum {
        return Err(exhausted());
    }
    let model = field(control, "model")?;
    let capacity = output_capacity(model)?;
    let state = field(model, "state")?;
    let mut outputs = Fields::array(field(state, "outputs")?)?;
    let mut initialized_outputs = 0usize;
    while outputs.next()?.is_some() {
        initialized_outputs = sum(&[initialized_outputs, 1])?;
    }
    outputs.finish()?;
    if initialized_outputs > capacity {
        return Err(exhausted());
    }
    let publication_slots = if initialized_outputs == 0 {
        0
    } else {
        mul(2, initialized_outputs)?.max(4)
    };
    // This is the existing initialized string-child census, not the raw body
    // length multiplied by a heap tax. Other model strings conservatively stay
    // included; caller-owned target/endpoint/proof strings remain independent.
    let strings = scan(
        model,
        maximum,
        size_of::<Value>(),
        map_node(
            size_of::<String>() + size_of::<Value>(),
            align_of::<Value>(),
        )?,
    )?
    .strings;
    Ok(PacketCompleteRestoreModelOutputPopulationData {
        initialized_outputs,
        publication_slots,
        owned_string_payload_backing: strings,
    })
}

/// Names the actual selected constructor and raw population counter views.
///
/// This is fixed requested-layout scratch, excluding compiler/recursive frames,
/// allocator overhead and all future scheduling observation owners.
pub fn complete_restore_selected_model_output_population_counter_scratch_data() -> usize {
    complete_restore_selected_owner_construction_counter_scratch_data()
        + selected_issuer_decode_counter_scratch_data()
        + size_of::<PacketCompleteRestoreModelOutputPopulationData>()
        + size_of::<Result<PacketCompleteRestoreModelOutputPopulationData, ProviderError>>()
        + size_of::<PacketCompleteRestoreOwnerValidationStorage>()
        + size_of::<Result<PacketCompleteRestoreOwnerValidationStorage, ProviderError>>()
        + 3 * size_of::<Fields<'static>>()
        + size_of::<Result<Fields<'static>, ProviderError>>()
        + size_of::<Result<&'static [u8], ProviderError>>()
        + size_of::<Result<Option<&'static [u8]>, ProviderError>>()
        + size_of::<Option<&'static [u8]>>()
        + size_of::<Result<Option<(&'static [u8], &'static [u8])>, ProviderError>>()
        + size_of::<Option<(&'static [u8], &'static [u8])>>()
        + size_of::<(&'static [u8], &'static [u8])>()
        + size_of::<bool>()
        + size_of::<&mut bool>()
        + size_of::<u64>()
        + size_of::<Result<&'static str, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<[bool; 6]>()
        + size_of::<std::array::IntoIter<bool, 6>>()
        + size_of::<[usize; 2]>()
        + size_of::<Credit>()
        + size_of::<Result<Credit, ProviderError>>()
        + size_of::<&PacketCompleteRestoreSelectedOwnerInputs<'static>>()
        + 4 * size_of::<&[u8]>()
        + size_of::<&str>()
        + size_of::<[usize; 8]>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_initialized_output_count_bounds_fallible_growth_independently_of_spare() {
        let control = br#"{"model":{"capacities":{"events":0,"reactions":0,"delivered_inputs":0,"publications":0,"outputs":9,"stages":0},"state":{"outputs":[{"event":"first","payload":"AQID"},{"event":"second","payload":"BAUG"}]}}}"#;
        let data = population_from_control(control, control.len()).unwrap();

        let value: Value = serde_json::from_slice(control).unwrap();
        let outputs = value["model"]["state"]["outputs"].as_array().unwrap();
        let collected = outputs
            .iter()
            .map(|_| Ok::<usize, ProviderError>(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut actual = crate::retained_metadata::MetadataObserver::new();
        for output in outputs {
            let id = output["event"].as_str().unwrap().to_owned();
            let payload: crucible_node_format::Bytes =
                serde_json::from_value(output["payload"].clone()).unwrap();
            actual.observe(&id).unwrap();
            actual.observe(&payload).unwrap();
        }
        let children =
            crate::retained_metadata::requested_metadata_backing_storage_data(&actual.finish())
                .unwrap();
        assert!(children <= data.owned_string_payload_backing_bytes_data());
        assert!(collected.capacity() <= data.publication_slots_data());

        assert_eq!(data.initialized_outputs_data(), 2);
        assert_eq!(data.publication_slots_data(), 4);
        assert!(
            data.owned_string_payload_backing_bytes_data() >= "first".len() + "second".len() + 6
        );
        assert!(population_from_control(control, control.len() - 1).is_err());
    }

    #[test]
    fn output_population_refuses_excess_initialized_missing_and_duplicate_capacity() {
        for control in [
            br#"{"model":{"capacities":{"events":0,"reactions":0,"delivered_inputs":0,"publications":0,"outputs":0,"stages":0},"state":{"outputs":[{}]}}}"#.as_slice(),
            br#"{"model":{"capacities":{"events":0,"reactions":0,"delivered_inputs":0,"publications":0,"outputs":0,"outputs":0,"stages":0},"state":{"outputs":[]}}}"#,
            br#"{"model":{"capacities":{"outputs":0},"state":{"outputs":[]}}}"#,
        ] {
            assert!(population_from_control(control, control.len()).is_err());
        }
        let empty = br#"{"model":{"capacities":{"events":0,"reactions":0,"delivered_inputs":0,"publications":0,"outputs":6,"stages":0},"state":{"outputs":[]}}}"#;
        let data = population_from_control(empty, empty.len()).unwrap();
        assert_eq!(data.initialized_outputs_data(), 0);
        assert_eq!(data.publication_slots_data(), 0);
    }
}
