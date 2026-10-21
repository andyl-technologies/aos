//! Shares the existing bounded Publisher record-key and array helpers.
//!
//! These private DATA helpers retain each concrete module's old error value;
//! they supply no native file, record admission or mutation exception.

/// Defines the unchanged private canonical key/array helper bodies.
#[macro_export]
macro_rules! define_provider_record_helpers_data_recipe_v1 {
    ($invalid:expr) => {
        $crate::define_provider_record_helpers_data_recipe_v1!(pub(super), $invalid);
    };
    ($visibility:vis, $invalid:expr) => {
        /// Encodes the established prefix, identity and optional generation key.
        $visibility fn key(prefix: &[u8], identity: &[u8], generation: Option<u64>) -> Vec<u8> {
            let mut key = Vec::with_capacity(prefix.len() + identity.len() + generation.map_or(0, |_| 8));
            key.extend_from_slice(prefix);
            key.extend_from_slice(identity);
            if let Some(generation) = generation {
                key.extend_from_slice(&generation.to_be_bytes());
            }
            key
        }
        /// Extracts one complete fixed-width field from supplied record bytes.
        ///
        /// # Errors
        /// Rejects a field outside the exact supplied record.
        $visibility fn array<const N: usize>(
            bytes: &[u8],
            offset: usize,
        ) -> Result<[u8; N], PublisherPolicyError> {
            bytes
                .get(offset..offset + N)
                .and_then(|slice| slice.try_into().ok())
                .ok_or($invalid)
        }
    };
}
