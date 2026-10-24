//! Borrows actual failed and incomplete token custody for passive history.
//!
//! A partial token stream may be unbalanced and its index may be unfinished.
//! These views never promote that retained prefix into assembled literal DATA.

use super::*;

/// Borrows actual attempt flags and every initialized token/cache/String bank.
///
/// The private constructor accepts only the actual immutable attempt. No field
/// grants assembly completion, Source identity, currentness or node execution.
/// A historical consumer preserves the flags and partial stream independently;
/// a successful-token reader cannot stand in for a partial-history reader.
pub(crate) struct LiteralValue18TokenAttemptPartialData<'a> {
    attempt: &'a LiteralValue18TokenAttempt,
}

impl<'a> LiteralValue18TokenAttemptPartialData<'a> {
    /// Returns all three actual once/failure/assembly bits independently.
    pub(crate) fn state_data(&self) -> (bool, bool, bool) {
        self.attempt.state_data()
    }

    /// Borrows every actual partial bank without the successful-assembly gate.
    pub(crate) fn data(&self) -> &'a LiteralValue18Data {
        &self.attempt.data
    }
}

impl LiteralValue18TokenAttempt {
    /// Borrows actual partial token custody without requiring assembly success.
    ///
    /// This passive view performs no validation, serialization, allocation,
    /// clone, extraction or reset. Callers separately fund any flat serializer,
    /// census, correspondence check or historical partial-reader construction.
    /// Existing data() and take_data_into() keep their completed-only guards.
    pub(crate) fn partial_data(&self) -> LiteralValue18TokenAttemptPartialData<'_> {
        LiteralValue18TokenAttemptPartialData { attempt: self }
    }

    /// Names only the actual passive view and its defining argument/field loans.
    ///
    /// Owning DATA census/serialization and enclosing Source loans are separate
    /// defining costs. No workspace or retained backing is constructed here.
    pub(crate) fn partial_counter_scratch_data() -> usize {
        size_of::<LiteralValue18TokenAttemptPartialData<'static>>()
            + size_of::<&Self>()
            + size_of::<&LiteralValue18TokenAttemptPartialData<'static>>()
            + size_of::<&LiteralValue18Data>()
            + size_of::<(bool, bool, bool)>()
            + size_of::<bool>() * 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unused_and_failed_prefix_views_keep_actual_custody_without_promotion() {
        let mut attempt = LiteralValue18TokenAttempt::new();
        let unused = attempt.partial_data();
        assert_eq!(unused.state_data(), (false, false, false));
        assert!(std::ptr::eq(unused.data(), &attempt.data));
        assert!(unused.data().chunks.is_empty());
        assert!(attempt.data().is_err());

        let raw = serde_json::json!({
            "schema": SCHEMA,
            "chunks": [[{"type":"arrayStart"}, {"type":"objectEnd"}]],
        });
        let row = quote_read_data(&raw, usize::MAX).unwrap();
        assert!(read_into_data(&raw, row, &mut attempt, usize::MAX).is_err());
        let before = attempt.retained_requested_storage_data(usize::MAX).unwrap();
        let failed = attempt.partial_data();
        assert_eq!(failed.state_data(), (true, true, false));
        assert!(std::ptr::eq(failed.data(), &attempt.data));
        assert_eq!(failed.data().chunks[0].len(), 2);
        assert!(matches!(
            failed.data().chunks[0][0],
            LiteralToken18::ArrayStart
        ));
        assert!(matches!(
            failed.data().chunks[0][1],
            LiteralToken18::ObjectEnd
        ));
        assert!(!failed.data().container_children.is_empty());
        assert!(attempt.data().is_err());

        let mut output = None;
        assert!(attempt.take_data_into(&mut output).is_err());
        assert!(output.is_none());
        assert!(read_into_data(&raw, row, &mut attempt, usize::MAX).is_err());
        assert_eq!(
            attempt.retained_requested_storage_data(usize::MAX).unwrap(),
            before
        );
        assert_eq!(attempt.partial_data().state_data(), (true, true, false));
    }

    #[test]
    fn completed_and_moved_views_report_only_their_actual_remaining_banks() {
        let value = serde_json::json!({"raw": null});
        let row = quote_encode_data(&value, 2, usize::MAX).unwrap();
        let mut attempt = LiteralValue18TokenAttempt::new();
        encode_into_data(&value, row, &mut attempt, usize::MAX).unwrap();
        let complete = attempt.partial_data();
        assert_eq!(complete.state_data(), (true, false, true));
        assert!(std::ptr::eq(complete.data(), attempt.data().unwrap()));
        let bank = complete.data().chunks[0].as_ptr();

        let mut output = None;
        attempt.take_data_into(&mut output).unwrap();
        let moved = attempt.partial_data();
        assert_eq!(moved.state_data(), (true, false, false));
        assert!(moved.data().chunks.is_empty());
        assert!(moved.data().container_children.is_empty());
        assert_eq!(output.as_ref().unwrap().chunks[0].as_ptr(), bank);
        assert!(attempt.data().is_err());
        assert!(LiteralValue18TokenAttempt::partial_counter_scratch_data() > 0);
    }
}
