//! Checks retained completed Capture content with fixed hash scratch only.
//!
//! The enclosing live SDK lender proves actual private once completion and
//! journal correspondence. This helper only verifies a full retained content
//! reference; it performs no fetch, allocation or portable-state admission.

use super::*;
use std::mem::size_of;

impl ClientContent {
    pub(in crate::client) fn original_completed_capture17_body_precredit_data(
        &self,
        reference: &ContentRef,
    ) -> Result<&[u8], ProviderError> {
        let (actual, bytes) = self
            .objects
            .get(&reference.hash.digest)
            .ok_or_else(refused)?;
        if actual != reference
            || reference.hash.algorithm != "blake3-256"
            || reference.hash.domain != "cnp.blob.v1"
            || reference.hash.digest.len() != 64
            || !reference
                .hash
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || u64::try_from(bytes.len()).ok() != Some(reference.length.get())
        {
            return Err(refused());
        }

        // The framing is canonical::hash's cnp.blob.v1 domain framing. Compare
        // borrowed hexadecimal digits to fixed digest bytes, never to a String.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CNP/1\0");
        hasher.update(&11u32.to_be_bytes());
        hasher.update(b"cnp.blob.v1");
        hasher.update(&reference.length.get().to_be_bytes());
        hasher.update(bytes);
        let digest = hasher.finalize();
        for (hex, byte) in reference
            .hash
            .digest
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .zip(digest.as_bytes())
        {
            if hex_digit(hex[0]) * 16 + hex_digit(hex[1]) != *byte {
                return Err(refused());
            }
        }
        Ok(bytes.as_slice())
    }

    pub(in crate::client) fn original_completed_capture17_body_precredit_counter_scratch_data()
    -> usize {
        size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<&ClientContent>()
            + size_of::<&ContentRef>() * 2
            + size_of::<&(ContentRef, Rc<Vec<u8>>)>()
            + size_of::<Option<&(ContentRef, Rc<Vec<u8>>)>>()
            + size_of::<Result<&[u8], ProviderError>>()
            + size_of::<&Rc<Vec<u8>>>()
            + size_of::<&[u8]>() * 3
            + size_of::<[u8; 4]>()
            + size_of::<[u8; 8]>()
            + size_of::<&[u8; 32]>()
            + size_of::<&[[u8; 2]]>()
            + size_of::<std::slice::Iter<'static, [u8; 2]>>()
            + size_of::<std::slice::Iter<'static, u8>>()
            + size_of::<
                std::iter::Zip<std::slice::Iter<'static, [u8; 2]>, std::slice::Iter<'static, u8>>,
            >()
            + size_of::<Option<(&[u8; 2], &u8)>>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<std::ops::RangeInclusive<u8>>()
            + size_of::<Option<u64>>()
            + size_of::<u64>()
            + size_of::<u8>() * 4
            + size_of::<bool>()
    }
}

fn hex_digit(value: u8) -> u8 {
    if value.is_ascii_digit() {
        value - b'0'
    } else {
        value - b'a' + 10
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("completed Capture17 retained content changed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn full_reference_and_body_are_checked_without_replacing_the_retained_bank() {
        let bytes = br#"{"native":"completed capture DATA"}"#.to_vec();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        let mut content = ClientContent::new(65_536, 8, 4096).unwrap();
        assert!(
            content
                .original_completed_capture17_body_precredit_data(&reference)
                .is_err()
        );

        let mut pending = Some((reference.clone(), bytes));
        content
            .install_original_host_startup_from_slot(&mut pending)
            .unwrap();
        assert!(pending.is_none());
        let pointer = content
            .original_completed_capture17_body_precredit_data(&reference)
            .unwrap()
            .as_ptr();

        let mut wrong = reference.clone();
        wrong.media_type = "text/plain".into();
        assert!(
            content
                .original_completed_capture17_body_precredit_data(&wrong)
                .is_err()
        );
        wrong = reference.clone();
        wrong.length = U64::new(reference.length.get() + 1);
        assert!(
            content
                .original_completed_capture17_body_precredit_data(&wrong)
                .is_err()
        );
        wrong = reference.clone();
        wrong.hash.domain = "different.domain".into();
        assert!(
            content
                .original_completed_capture17_body_precredit_data(&wrong)
                .is_err()
        );

        assert_eq!(
            content
                .original_completed_capture17_body_precredit_data(&reference)
                .unwrap()
                .as_ptr(),
            pointer
        );
        assert_eq!(content.objects.len(), 1);
        assert!(content.transfers.is_empty());
    }

    #[test]
    fn changed_retained_bytes_refuse_even_with_the_same_map_key_and_full_reference() {
        let bytes = br#"{"native":"completed capture DATA"}"#.to_vec();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        let mut content = ClientContent::new(65_536, 8, 4096).unwrap();
        let mut pending = Some((reference.clone(), bytes));
        content
            .install_original_host_startup_from_slot(&mut pending)
            .unwrap();
        let (_, bank) = content.objects.get_mut(&reference.hash.digest).unwrap();
        let pointer = bank.as_ptr();
        Rc::get_mut(bank).unwrap()[0] ^= 1;

        assert!(
            content
                .original_completed_capture17_body_precredit_data(&reference)
                .is_err()
        );
        assert_eq!(
            content
                .objects
                .get(&reference.hash.digest)
                .unwrap()
                .1
                .as_ptr(),
            pointer
        );
        assert_eq!(content.objects.len(), 1);
    }

    #[test]
    fn malformed_retained_hash_spelling_does_not_reach_digit_decoding() {
        let bytes = b"retained DATA".to_vec();
        let mut reference = canonical::content_ref(&bytes, "application/json").unwrap();
        reference.hash.digest.replace_range(..1, "G");
        let mut content = ClientContent::new(65_536, 8, 4096).unwrap();
        content.objects.insert(
            reference.hash.digest.clone(),
            (reference.clone(), Rc::new(bytes)),
        );

        assert!(
            content
                .original_completed_capture17_body_precredit_data(&reference)
                .is_err()
        );
        assert_eq!(content.objects.len(), 1);
    }
}
