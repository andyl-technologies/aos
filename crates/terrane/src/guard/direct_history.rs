//! Owns invocation-local native completion of immutable historical verification.
//!
//! Direct verification has no token, current-ref permission or mutation purpose.
//! Its implementation must keep the full semantic walk and physical closure
//! separate from current, held-authorization and candidate completion.

#[cfg(test)]
mod tests;
