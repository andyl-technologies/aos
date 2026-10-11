//! Finite original common association credit before copies and native dispatch.

use std::io::{self, Write};

use serde::Serialize;

use crate::node_contract::OperationFailure;

use super::refused;

#[derive(Default)]
pub(super) struct SemanticCredit {
    retained: usize,
}

impl SemanticCredit {
    pub(super) fn reserve_bytes(
        &mut self,
        bytes: usize,
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        let total = self
            .retained
            .checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| refused("generic semantic retained credit is exhausted"))?;
        self.retained = total;
        Ok(())
    }

    pub(super) fn reserve(
        &mut self,
        value: &impl Serialize,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        let remaining = maximum
            .checked_sub(self.retained)
            .ok_or_else(|| refused("generic semantic retained credit is exhausted"))?;
        let charged = serialized_size(value, remaining)?;
        self.retained += charged;
        Ok(charged)
    }
}

pub(super) fn serialized_size(
    value: &impl Serialize,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    struct Counter {
        retained: usize,
        maximum: usize,
    }

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let total = self
                .retained
                .checked_add(bytes.len())
                .filter(|total| *total <= self.maximum)
                .ok_or_else(|| io::Error::other("generic source byte credit exceeded"))?;
            self.retained = total;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter {
        retained: 0,
        maximum,
    };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| refused("generic source byte credit exceeded before copies"))?;
    Ok(counter.retained)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_callback_credit_is_atomic_before_owned_results() {
        let mut credit = SemanticCredit::default();
        assert!(credit.reserve_bytes(4096, 4096).is_ok());
        assert!(credit.reserve_bytes(1, 4096).is_err());
        assert_eq!(credit.retained, 4096);
        assert!(credit.reserve_bytes(usize::MAX, usize::MAX).is_err());
        assert_eq!(credit.retained, 4096);
    }

    #[test]
    fn sizing_charges_actual_escaped_wire_extent_before_copy() {
        let source = "\0".repeat(64);
        let required = 64 * 6 + 2;
        assert_eq!(serialized_size(&source, required).ok(), Some(required));
        assert!(serialized_size(&source, required - 1).is_err());
        let mut credit = SemanticCredit::default();
        assert!(credit.reserve(&source, required - 1).is_err());
        assert_eq!(credit.retained, 0);
    }
}
