//! Exact nonnegative decimal strings used by the closed control wire.
//!
//! ```json
//! "9007199254740993"
//! ```

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Exact unsigned integer serialized as a canonical decimal string.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct WireInteger(u64);

impl WireInteger {
    /// Constructs an exact unsigned integer without floating-point conversion.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the exact unsigned value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Serialize for WireInteger {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for WireInteger {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty()
            || text.len() > 20
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || (text.len() > 1 && text.starts_with('0'))
        {
            return Err(serde::de::Error::custom("invalid exact decimal integer"));
        }
        text.parse()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("exact decimal integer overflow"))
    }
}
