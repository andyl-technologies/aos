//! Supplies a deterministic value for cross-derivation cache qualification.

/// Returns the fixture's shared library value.
pub fn answer() -> u32 {
    42
}

#[cfg(test)]
mod tests {
    #[test]
    fn returns_expected_answer() {
        assert_eq!(super::answer(), 42);
    }
}
