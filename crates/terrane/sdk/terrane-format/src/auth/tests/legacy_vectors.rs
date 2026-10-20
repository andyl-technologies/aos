//! Compares the complete published token with an ordinary unverified model.
//!
//! Private access preserves every body, next key and opaque signature without
//! issuing, signing, attenuating or constructing authenticated authority.

#![allow(clippy::unwrap_used, reason = "published models must match exactly")]

use crate as core_model;
use crate::auth::{Signed, Token};

#[path = "../../../tests/legacy_vectors/support.rs"]
mod support;
#[path = "../../../tests/legacy_vectors/token_model.rs"]
mod token_model;

#[test]
fn published_token_private_fields_match_separately_constructed_model() {
    let model = Token {
        authority: Signed {
            body: token_model::authority(),
            next_key: token_model::next_key(),
            signature: token_model::authority_signature(),
        },
        blocks: alloc::vec![Signed {
            body: token_model::attenuation(),
            next_key: token_model::next_key(),
            signature: token_model::attenuation_signature(),
        }],
    };
    let published = support::wire("## Capability token", 2);

    assert_eq!(token_model::wire_projection(), published);
    assert_eq!(model.encode(), published);
    assert_eq!(Token::decode(&published).unwrap(), model);
}
