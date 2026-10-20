//! Compares prepared literal tokens with their actual immutable Value loan.
//!
//! The independently admitted iterator bank is disposable transient storage.
//! No Value clone, recursive equality or reconstructed deep owner is needed.

use super::*;

impl LiteralValue18Data {
    /// Quotes a disposable comparison bank from an actual retained population.
    ///
    /// The caller funds this row before borrowing the same Source/SDK Value.
    /// `observed_nodes` comes from that owner's separately funded census; a
    /// negotiated ceiling or token count is not a substitute for that census.
    /// All iterator loans end before the caller observes its whole holder.
    ///
    /// # Errors
    /// Refuses checked population/layout overflow or an independent ceiling.
    pub(crate) fn literal_match_prewalk_data(
        observed_nodes: usize,
        maximum: usize,
    ) -> Result<LiteralValue18Storage, RuntimeError> {
        LiteralValue18Storage::new(
            0,
            observed_nodes
                .checked_mul(size_of::<walk::Frame<'_>>())
                .ok_or(RuntimeError::ResourceLimit)?,
            Self::literal_match_counter_scratch_data(),
            maximum,
        )
    }

    /// Compares every literal token with the actual borrowed Value chronology.
    ///
    /// The caller independently admits literal_match_prewalk_data before this
    /// synchronous immutable loan. Exact keys, text, container boundaries and
    /// integer/float representations must match, including float negative zero.
    /// Chunk boundaries are storage framing and do not change literal identity.
    /// Success proves only DATA correspondence and supplies no currentness,
    /// Source identity, completed observation or permission to execute a node.
    ///
    /// # Errors
    /// Refuses insufficient actual population, workspace allocation failure,
    /// unsupported numeric representation or an independent construction bound.
    pub(crate) fn matches_literal_data(
        &self,
        value: &Value,
        observed_nodes: usize,
        maximum: usize,
    ) -> Result<bool, RuntimeError> {
        Self::literal_match_prewalk_data(observed_nodes, maximum)?;
        let mut walker = walk::Walker::new(value, observed_nodes)?;
        let mut prepared = self.chunks.iter().flatten();
        loop {
            let actual = walker.next()?;
            let expected = prepared.next();
            match (expected, actual) {
                (None, None) => return Ok(true),
                (Some(expected), Some(actual)) if matches_token(expected, actual) => {}
                _ => return Ok(false),
            }
        }
    }

    /// Names this comparison's own views and its actual traversal/row helpers.
    pub(crate) fn literal_match_counter_scratch_data() -> usize {
        geometry::traversal_counter_scratch_data()
            + geometry::checked_row_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&Value>()
            + size_of::<std::slice::Iter<'static, Vec<LiteralToken18>>>()
            + size_of::<std::slice::Iter<'static, LiteralToken18>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'static, Vec<LiteralToken18>>>>()
            + size_of::<&Vec<LiteralToken18>>()
            + size_of::<&LiteralToken18>()
            + size_of::<Option<&LiteralToken18>>()
            + size_of::<walk::BorrowedToken18<'static>>()
            + size_of::<Option<walk::BorrowedToken18<'static>>>()
            + size_of::<(
                Option<&LiteralToken18>,
                Option<walk::BorrowedToken18<'static>>,
            )>()
            + size_of::<(&LiteralToken18, walk::BorrowedToken18<'static>)>()
            + size_of::<Result<walk::Walker<'static>, RuntimeError>>()
            + size_of::<&bool>()
            + size_of::<&String>()
            + size_of::<&str>() * 2
            + size_of::<&U64>()
            + size_of::<u64>()
            + size_of::<bool>() * 2
            + size_of::<usize>() * 2
            + size_of::<Result<bool, RuntimeError>>()
    }
}

fn matches_token(expected: &LiteralToken18, actual: walk::BorrowedToken18<'_>) -> bool {
    use walk::BorrowedToken18 as Borrowed;
    match (expected, actual) {
        (LiteralToken18::Null, Borrowed::Null)
        | (LiteralToken18::ArrayStart, Borrowed::ArrayStart)
        | (LiteralToken18::ArrayEnd, Borrowed::ArrayEnd)
        | (LiteralToken18::ObjectStart, Borrowed::ObjectStart)
        | (LiteralToken18::ObjectEnd, Borrowed::ObjectEnd) => true,
        (LiteralToken18::Bool(expected), Borrowed::Bool(actual)) => *expected == actual,
        (LiteralToken18::Unsigned(expected), Borrowed::Unsigned(actual))
        | (LiteralToken18::Signed(expected), Borrowed::Signed(actual))
        | (LiteralToken18::FloatBits(expected), Borrowed::FloatBits(actual)) => {
            expected.get() == actual
        }
        (LiteralToken18::String(expected), Borrowed::String(actual))
        | (LiteralToken18::Key(expected), Borrowed::Key(actual)) => expected == actual,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(value: &Value, nodes: usize) -> LiteralValue18TokenAttempt {
        let quote = quote_encode_data(value, nodes, usize::MAX).unwrap();
        let mut attempt = LiteralValue18TokenAttempt::new();
        encode_into_data(value, quote, &mut attempt, usize::MAX).unwrap();
        attempt
    }

    #[test]
    fn correspondence_preserves_numeric_variants_and_literal_raw_keys() {
        let samples = [
            Value::Null,
            serde_json::json!(false),
            serde_json::json!(u64::MAX),
            serde_json::json!(-1),
            serde_json::json!(1.0),
            serde_json::json!(-0.0),
            serde_json::json!(0.0),
            serde_json::json!("literal"),
            serde_json::json!([1]),
            serde_json::json!({"key": 1}),
            serde_json::json!({"$serde_json::private::RawValue": "null"}),
        ];
        for (index, value) in samples.iter().enumerate() {
            let attempt = encode(value, 2);
            for (other, candidate) in samples.iter().enumerate() {
                assert_eq!(
                    attempt
                        .data()
                        .unwrap()
                        .matches_literal_data(candidate, 2, usize::MAX)
                        .unwrap(),
                    index == other,
                );
            }
        }
    }

    #[test]
    fn correspondence_rejects_changed_keys_shapes_lengths_and_text() {
        let original = serde_json::json!({"a": ["before", null], "b": {}});
        let attempt = encode(&original, 5);
        for changed in [
            serde_json::json!({"a": ["after", null], "b": {}}),
            serde_json::json!({"a": ["before"], "b": {}}),
            serde_json::json!({"a": ["before", null, null], "b": {}}),
            serde_json::json!({"a": ["before", null], "c": {}}),
            serde_json::json!({"a": ["before", null], "b": []}),
        ] {
            assert!(
                !attempt
                    .data()
                    .unwrap()
                    .matches_literal_data(&changed, 6, usize::MAX)
                    .unwrap()
            );
        }
        assert!(
            attempt
                .data()
                .unwrap()
                .matches_literal_data(&original, 5, usize::MAX)
                .unwrap()
        );
    }

    #[test]
    fn correspondence_admits_exact_row_and_refuses_one_short_population() {
        let value = serde_json::json!([[null]]);
        let attempt = encode(&value, 3);
        let row = LiteralValue18Data::literal_match_prewalk_data(3, usize::MAX).unwrap();
        let (r, t, s) = row.requested_storage_data();
        assert_eq!(r, 0);
        assert!(t > 0 && s > 0);
        let exact = r + t + s;
        assert!(
            attempt
                .data()
                .unwrap()
                .matches_literal_data(&value, 3, exact)
                .unwrap()
        );
        assert!(matches!(
            attempt
                .data()
                .unwrap()
                .matches_literal_data(&value, 3, exact - 1),
            Err(RuntimeError::ResourceLimit),
        ));
        assert!(matches!(
            attempt
                .data()
                .unwrap()
                .matches_literal_data(&value, 2, usize::MAX),
            Err(RuntimeError::ResourceLimit),
        ));
        assert!(
            attempt
                .data()
                .unwrap()
                .matches_literal_data(&value, 3, exact)
                .unwrap()
        );
    }

    #[test]
    fn deep_correspondence_uses_only_borrowed_disposable_frames() {
        let depth = 32_768;
        let mut tokens = Vec::new();
        tokens.extend((0..depth).map(|_| serde_json::json!({"type":"arrayStart"})));
        tokens.push(serde_json::json!({"type":"floatBits", "value": "9223372036854775808"}));
        tokens.extend((0..depth).map(|_| serde_json::json!({"type":"arrayEnd"})));
        let chunks: Vec<_> = tokens
            .chunks(MAX_ARRAY_ELEMENTS)
            .map(|chunk| chunk.to_vec())
            .collect();
        let wire = serde_json::json!({"schema": SCHEMA, "chunks": chunks});
        let quote = quote_read_data(&wire, usize::MAX).unwrap();
        let mut prepared = LiteralValue18TokenAttempt::new();
        read_into_data(&wire, quote, &mut prepared, usize::MAX).unwrap();
        let data = prepared.data().unwrap();
        let quote = quote_decode_data(data, usize::MAX).unwrap();
        let mut decoded = LiteralValue18DecodeAttempt::new();
        decode_into_data(data, quote, &mut decoded, usize::MAX).unwrap();
        let before = decoded.state_data();
        assert!(
            data.matches_literal_data(decoded.value().unwrap(), depth + 1, usize::MAX)
                .unwrap()
        );
        assert!(matches!(
            data.matches_literal_data(decoded.value().unwrap(), depth, usize::MAX),
            Err(RuntimeError::ResourceLimit)
        ));
        assert_eq!(decoded.state_data(), before);
        // Both comparison calls disposed only borrowed workspace; the deep
        // actual Value remains under its independently funded iterative Drop.
    }
}
