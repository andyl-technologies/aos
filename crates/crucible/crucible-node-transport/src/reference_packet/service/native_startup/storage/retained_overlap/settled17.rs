//! Preserves an original overlap quote and borrowed identity relationships as DATA.
//!
//! Identity tokens are compared only by a caller-precharged pass-local lookup.
//! They are never dereferenced, encoded as addresses, or used to issue credit.
//!
//! ```text
//! {origin_role,input_roles,inputs,input_lengths,private_retained,native_retained,overlap}
//! ```

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct History<'a, R> {
    original: &'a PacketNativeBirthRetainedOverlapData,
    roles: R,
}

impl PacketNativeBirthRetainedOverlapData {
    /// Borrows the complete quote and resolves its original input identities.
    ///
    /// The resolver receives opaque comparison tokens only. It must not
    /// dereference them or encode their addresses. Its output names historical
    /// alias groups and never grants access to either original input.
    ///
    /// # Errors
    /// Refuses a foreign process/thread or the resolver's original finite bank.
    pub fn borrowed_settled17_history_data<'a, R: Serialize + 'a>(
        &'a self,
        resolve: impl FnOnce(
            *const PacketNative5SourceLaunch,
            *const crucible_node_format::Id,
        ) -> Result<R, ProviderError>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.origin()?;
        let roles = resolve(self.launch, self.private_launch)?;
        Ok(History {
            original: self,
            roles,
        })
    }

    /// Counts fixed defining quote, digest and identity-token views.
    ///
    /// The caller independently counts the concrete resolver output and views.
    pub fn settled17_history_counter_scratch_data<R>() -> usize {
        size_of::<History<'static, R>>()
            + size_of::<Result<History<'static, R>, ProviderError>>()
            + size_of::<[&usize; 3]>()
            + size_of::<(
                *const PacketNative5SourceLaunch,
                *const crucible_node_format::Id,
            )>()
            + size_of::<BorrowedCompactBytes<'static>>()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl<R: Serialize> Serialize for History<'_, R> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.original.origin().map_err(S::Error::custom)?;
        let PacketNativeBirthRetainedOverlapData {
            process: _,
            thread: _,
            launch: _,
            private_launch: _,
            inputs,
            input_lengths,
            private_retained,
            native_retained,
            overlap,
        } = self.original;
        let mut state = serializer.serialize_struct("HistoricalBirthOverlap17", 7)?;
        state.serialize_field("origin_role", "original-source-process-thread")?;
        state.serialize_field("input_roles", &self.roles)?;
        state.serialize_field("inputs", &BorrowedCompactBytes::new(inputs.as_bytes()))?;
        state.serialize_field("input_lengths", input_lengths)?;
        state.serialize_field("private_retained", private_retained)?;
        state.serialize_field("native_retained", native_retained)?;
        state.serialize_field("overlap", overlap)?;
        let result = state.end()?;
        self.original.origin().map_err(S::Error::custom)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_overlap_resolves_tokens_without_encoding_addresses_or_regranting_inputs() {
        // An inert quote is not genuine input evidence or a startup member.
        let quote = PacketNativeBirthRetainedOverlapData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            launch: std::ptr::null(),
            private_launch: std::ptr::null(),
            inputs: blake3::hash(b"historical input DATA"),
            input_lengths: [7, 11, 13],
            private_retained: 41,
            native_retained: 43,
            overlap: 17,
        };
        let history = quote
            .borrowed_settled17_history_data(|launch, private| {
                assert!(launch.is_null());
                assert!(private.is_null());
                Ok(("historical-launch-alias", "historical-private-launch-alias"))
            })
            .unwrap();
        let body = serde_json::to_value(history).unwrap();

        assert_eq!(
            body["input_roles"],
            serde_json::json!(["historical-launch-alias", "historical-private-launch-alias"])
        );
        assert_eq!(body["input_lengths"], serde_json::json!([7, 11, 13]));
        assert_eq!(body["private_retained"], 41);
        assert_eq!(body["native_retained"], 43);
        assert_eq!(body["overlap"], 17);
        assert!(body.get("launch").is_none());
        assert!(body.get("private_launch").is_none());
        assert!(quote.launch.is_null());
        assert!(quote.private_launch.is_null());
    }
}
