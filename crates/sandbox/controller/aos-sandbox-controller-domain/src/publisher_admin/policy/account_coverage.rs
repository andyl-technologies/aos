//! Private canonical account-companion DATA and checked obligation folding.
//!
//! This child owns neither an authority nor another account/Journal reducer.
//! Original owner comparison, enrollment, native co-commit and currentness are
//! mandatory separate joins at the actual Publisher store and cohort owner.
//!
//! ```text
//! AOSGUBC1 header228 | owner140[<=16] | obligation312[<=64] | checksum32
//! account-coverage/<project16><generationBE64>
//! UUID = SHA256(transaction-domain || bytes excluding UUID/checksum)[0..16]
//! owner disposition: 0 = native COMMIT, 1 = empty native, 2 = physical empty
//! ```

aos_sandbox_protocol::define_provider_account_coverage_data_recipe_v1!(
    super::PublisherPolicyError::CorruptState
);
