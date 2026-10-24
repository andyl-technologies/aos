//! Reserves only the separately admitted selected two-proof lifecycle quota.
//!
//! This changes finite counters, not allocation or Source authority. The same
//! outer one-shot action is spent before entry. Existing immutable objects and
//! transfer identities remain held; the absolute selected caps are unchanged.

use super::*;

impl ClientContent {
    pub(in crate::client) fn prepare_original_host_initial_capacity_data(
        &mut self,
    ) -> Result<(), ProviderError> {
        if !self.transfers.is_empty() || self.reserved > self.maximum_bytes {
            return Err(refused());
        }
        let bytes = self
            .maximum_bytes
            .checked_add(2 * 65_536)
            .filter(|value| *value <= 512 * 1024 * 1024)
            .ok_or_else(refused)?;
        let objects = self
            .maximum_objects
            .checked_add(2)
            .filter(|value| *value <= 4096)
            .ok_or_else(refused)?;
        self.maximum_bytes = bytes;
        self.maximum_objects = objects;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original host initial content quota")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_filled_content_gets_only_closed_two_proof_window() {
        let bytes = b"actual retained installed original".to_vec();
        let reference =
            crucible_node_format::canonical::content_ref(&bytes, "application/json").unwrap();
        let mut content = ClientContent::new(bytes.len(), 1, 4096).unwrap();
        content.install(reference.clone(), bytes.clone()).unwrap();
        assert!(content.preflight_capacity(2, 2 * 65_536).is_err());
        content
            .prepare_original_host_initial_capacity_data()
            .unwrap();
        content.preflight_capacity(2, 2 * 65_536).unwrap();
        assert!(content.preflight_capacity(3, 2 * 65_536).is_err());
        assert!(content.preflight_capacity(2, 2 * 65_536 + 1).is_err());
        assert_eq!(content.get(&reference).unwrap(), bytes.as_slice());
        assert!(content.transfers.is_empty());
    }
}
