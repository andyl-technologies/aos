//! Tests the public untrusted context validator independently of verified history.
//!
//! ```text
//! [version, view, domain, selector-bytes, baseline-or-null, minimum,
//!  ? selected-side-evidence-bytes]
//! ```
//!
//! Independent field models exercise validation and canonical byte structure.
//! The verified history-dependent context encoder remains a separate test gap.

use super::support::{Generator, cbor_properties, maximum_key};
use terrane_format::cbor::{self, Decoder};
use terrane_format::provenance::{Preset, Selector, validate_canonical_context};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContextModel {
    view: [u8; 32],
    domain: String,
    selector: Vec<u8>,
    baseline: Option<String>,
    minimum: u64,
    selected: Option<Vec<u8>>,
}

impl ContextModel {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![];
        cbor::write_array(&mut bytes, if self.selected.is_some() { 7 } else { 6 });
        cbor::write_uint(&mut bytes, if self.selected.is_some() { 2 } else { 1 });
        cbor::write_bytes(&mut bytes, &self.view);
        cbor::write_text(&mut bytes, &self.domain);
        cbor::write_bytes(&mut bytes, &self.selector);
        if let Some(baseline) = &self.baseline {
            cbor::write_text(&mut bytes, baseline);
        } else {
            bytes.push(0xf6);
        }
        cbor::write_uint(&mut bytes, self.minimum);
        if let Some(selected) = &self.selected {
            cbor::write_bytes(&mut bytes, selected);
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, terrane_format::provenance::Rejected> {
        use terrane_format::provenance::Rejected;
        validate_canonical_context(bytes)?;
        let mut decoder = Decoder::new(bytes);
        let count = decoder.array(7).map_err(|_| Rejected)?;
        decoder.uint().map_err(|_| Rejected)?;
        let view = decoder
            .bytes(32)
            .map_err(|_| Rejected)?
            .try_into()
            .map_err(|_| Rejected)?;
        let domain = decoder.text(bytes.len()).map_err(|_| Rejected)?.into();
        let selector = decoder.bytes(bytes.len()).map_err(|_| Rejected)?.into();
        let baseline = if decoder.peek_major().map_err(|_| Rejected)? == 7 {
            decoder.simple().map_err(|_| Rejected)?;
            None
        } else {
            Some(decoder.text(bytes.len()).map_err(|_| Rejected)?.into())
        };
        let minimum = decoder.uint().map_err(|_| Rejected)?;
        let selected = if count == 7 {
            Some(decoder.bytes(bytes.len()).map_err(|_| Rejected)?.into())
        } else {
            None
        };
        decoder.finish().map_err(|_| Rejected)?;
        Ok(Self {
            view,
            domain,
            selector,
            baseline,
            minimum,
            selected,
        })
    }
}

#[derive(Clone)]
struct SelectedRow {
    view: Vec<u8>,
    root: [u8; 32],
    path: Vec<u8>,
    name: String,
    domain: String,
    side_name: String,
    record: Vec<u8>,
    value: Vec<u8>,
    producer: [u8; 32],
    carrying_commit: [u8; 32],
    row_width: usize,
    tuple_width: usize,
}

fn location(bytes: &mut Vec<u8>, commit: &[u8], root: &[u8], path: &[u8]) {
    cbor::write_array(bytes, 3);
    cbor::write_bytes(bytes, commit);
    cbor::write_bytes(bytes, root);
    cbor::write_bytes(bytes, path);
}

impl SelectedRow {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![];
        cbor::write_array(&mut bytes, self.row_width);
        location(&mut bytes, &self.view, &self.root, &self.path);
        cbor::write_text(&mut bytes, &self.name);
        cbor::write_text(&mut bytes, &self.domain);
        cbor::write_bytes(&mut bytes, &self.path);

        if self.row_width == 4 {
            return bytes;
        }

        cbor::write_array(&mut bytes, self.tuple_width);
        cbor::write_bytes(&mut bytes, &self.record);
        cbor::write_bytes(&mut bytes, &[7; 32]);
        cbor::write_text(&mut bytes, &self.side_name);
        cbor::write_text(&mut bytes, "sha256");
        cbor::write_text(&mut bytes, "1");
        cbor::write_bytes(&mut bytes, &self.value);
        cbor::write_bytes(&mut bytes, &self.producer);
        location(&mut bytes, &self.carrying_commit, &[8; 32], &self.path);
        if self.tuple_width >= 9 {
            cbor::write_array(&mut bytes, 2);
            cbor::write_text(&mut bytes, "public");
            cbor::write_bytes(&mut bytes, &self.path);
        }
        if self.tuple_width == 10 {
            bytes.push(0xf6);
        }
        if self.row_width == 6 {
            bytes.push(0xf6);
        }
        bytes
    }
}

fn selected(rows: &[SelectedRow]) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_array(&mut bytes, rows.len());
    for row in rows {
        bytes.extend_from_slice(&row.encode());
    }
    bytes
}

fn row(generator: &mut Generator, context: &ContextModel, index: u8, path: Vec<u8>) -> SelectedRow {
    let mut root = generator.bytes();
    root[0] = index;
    let mut value = vec![];
    cbor::write_bytes(&mut value, &generator.bytes::<32>());
    SelectedRow {
        view: context.view.to_vec(),
        root,
        path,
        name: "hash.sha256".into(),
        domain: context.domain.clone(),
        side_name: "hash.sha256".into(),
        record: generator.bytes::<32>().to_vec(),
        value,
        producer: generator.bytes(),
        // Unsigned inline evidence may be carried by a different view. Schema
        // validation must not invent detached-signature authority for it.
        carrying_commit: generator.bytes(),
        row_width: 5,
        tuple_width: 9,
    }
}

#[test]
fn untrusted_context_models_cover_both_versions_and_selected_evidence_boundaries() {
    let mut generator = Generator::new(0x6f01_2748_b825_c6a9);
    for case in 0..24 {
        let mut model = ContextModel {
            view: generator.bytes(),
            domain: [
                "public",
                "tenant:generated",
                "group:generated",
                "private:generated",
            ][case % 4]
                .into(),
            selector: Selector::preset(
                [
                    Preset::Any,
                    Preset::SignedBaseline,
                    Preset::Strict,
                    Preset::Attested,
                ][case % 4],
            )
            .encode()
            .to_vec(),
            baseline: match case % 3 {
                0 => None,
                1 => Some(String::new()),
                _ => Some("baseline".into()),
            },
            minimum: [0, 262144, 1048576, u64::MAX][case % 4],
            selected: None,
        };
        for version in [1, 2] {
            if version == 2 {
                let path = match case % 4 {
                    0 => b"a".to_vec(),
                    1 => b"file".to_vec(),
                    2 => vec![b'p'; 255],
                    _ => maximum_key().into_bytes(),
                };
                let rows = (0..[1, 2, 7][case % 3])
                    .map(|index| row(&mut generator, &model, index, path.clone()))
                    .collect::<Vec<_>>();
                model.selected = Some(selected(&rows));
            }
            let bytes = model.encode();
            assert_eq!(ContextModel::decode(&bytes).unwrap(), model);
            assert_eq!(model.clone().encode(), bytes);
            cbor_properties("untrusted context validator", &bytes, |input| {
                Ok::<_, terrane_format::provenance::Rejected>(ContextModel::decode(input)?.encode())
            });
        }
    }
}

#[test]
fn selected_context_schema_rejects_malformed_rows_and_nested_value_encodings() {
    let mut generator = Generator::new(0xda7b_0533_a428_19c1);
    let mut context = ContextModel {
        view: generator.bytes(),
        domain: "public".into(),
        selector: Selector::preset(Preset::Any).encode().to_vec(),
        baseline: None,
        minimum: 262144,
        selected: None,
    };
    let first = row(&mut generator, &context, 0, b"file".to_vec());
    let second = row(&mut generator, &context, 1, b"file".to_vec());
    let mut malformed = vec![
        ("non-tuple row", vec![0x81, 0x01]),
        ("empty selection", vec![0x80]),
    ];
    for width in [4, 6] {
        let mut altered = first.clone();
        altered.row_width = width;
        malformed.push(("row width", selected(&[altered])));
    }
    for width in [8, 10] {
        let mut altered = first.clone();
        altered.tuple_width = width;
        malformed.push(("side tuple width", selected(&[altered])));
    }
    for length in [31, 33] {
        let mut altered = first.clone();
        altered.record.resize(length, 0);
        malformed.push(("record digest width", selected(&[altered])));
    }
    let mut altered = first.clone();
    altered.path.clear();
    malformed.push(("empty file path", selected(&[altered])));
    let mut altered = first.clone();
    altered.path = vec![b'x'; 256];
    malformed.push(("component limit", selected(&[altered])));
    let mut altered = first.clone();
    altered.path = vec![b'x'; 4097];
    malformed.push(("path limit", selected(&[altered])));
    let mut altered = first.clone();
    altered.view[0] ^= 1;
    malformed.push(("view agreement", selected(&[altered])));
    let mut altered = first.clone();
    altered.domain = "tenant:other".into();
    malformed.push(("domain agreement", selected(&[altered])));
    let mut altered = first.clone();
    altered.side_name = "hash.sha512".into();
    malformed.push(("name agreement", selected(&[altered])));
    let mut altered = first.clone();
    altered.value = vec![0x18, 0x01];
    malformed.push(("noncanonical value", selected(&[altered])));
    malformed.push(("duplicate row", selected(&[first.clone(), first.clone()])));
    malformed.push(("reordered rows", selected(&[second, first])));

    let mut accepted = vec![];
    for (name, evidence) in malformed {
        context.selected = Some(evidence);
        if validate_canonical_context(&context.encode()).is_ok() {
            accepted.push(name);
        }
    }
    assert!(
        accepted.is_empty(),
        "validator accepted malformed selected-side evidence: {accepted:?}"
    );
}
