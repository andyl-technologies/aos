//! By-value runtime `Value` layouts shared by interpreter and native tiers.
//!
//! The active evaluator still uses the 16-byte tag/payload pair. Candidate C
//! is described separately so JIT and FFI adapters can prove their one-word
//! lowering before the active representation changes.

const ACTIVE_VALUE_LAYOUT: RuntimeAbiValueLayout = RuntimeAbiValueLayout::new(16, 2, 8);
const CANDIDATE_C_VALUE_LAYOUT: RuntimeAbiValueLayout = RuntimeAbiValueLayout::new(8, 1, 8);

/// Returns the by-value runtime layout currently used at native call boundaries.
pub const fn runtime_abi_value_layout() -> RuntimeAbiValueLayout {
    ACTIVE_VALUE_LAYOUT
}

/// Returns the inactive Candidate-C compressed-word runtime layout.
pub const fn candidate_c_runtime_abi_value_layout() -> RuntimeAbiValueLayout {
    CANDIDATE_C_VALUE_LAYOUT
}

/// Describes how one runtime `Value` crosses a native call boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAbiValueLayout {
    size_bytes: usize,
    register_words: usize,
    register_word_bytes: usize,
}

impl RuntimeAbiValueLayout {
    const fn new(size_bytes: usize, register_words: usize, register_word_bytes: usize) -> Self {
        Self {
            size_bytes,
            register_words,
            register_word_bytes,
        }
    }

    /// Returns the by-value `Value` size expected at native call boundaries.
    pub const fn size_bytes(self) -> usize {
        self.size_bytes
    }

    /// Returns the number of machine words used to pass a `Value` in registers.
    pub const fn register_words(self) -> usize {
        self.register_words
    }

    /// Returns the byte width of each register-passed `Value` word.
    pub const fn register_word_bytes(self) -> usize {
        self.register_word_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_and_candidate_c_layouts_are_distinct_and_self_consistent() {
        let active = runtime_abi_value_layout();
        let candidate = candidate_c_runtime_abi_value_layout();

        assert_eq!(active.size_bytes(), 16);
        assert_eq!(active.register_words(), 2);
        assert_eq!(active.register_word_bytes(), 8);
        assert_eq!(candidate.size_bytes(), 8);
        assert_eq!(candidate.register_words(), 1);
        assert_eq!(candidate.register_word_bytes(), 8);
        assert_eq!(active.size_bytes(), active.register_words() * 8);
        assert_eq!(candidate.size_bytes(), candidate.register_words() * 8);
    }
}
