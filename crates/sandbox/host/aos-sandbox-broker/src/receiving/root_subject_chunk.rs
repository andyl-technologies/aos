//! Shares the fixed subject-chunk control order between genuine owners.
//!
//! Private lexical adapters retain their own actual frame, subject, post, clock
//! and failure custody. The fixed schedule adds no runtime callback or carrier,
//! constructs no role and accepts no completed-result or byte-buffer grant.

/// Expands the sole fixed subject-chunk schedule at its actual owner.
///
/// The private lexical adapter expands each stage in its actual owner's frame.
/// Each stage preserves its own original effects, errors and disposal. Only
/// positive completion disposes a chunk before the next iteration; a failed
/// receive still reaches its independent after and clock posts.
#[doc(hidden)]
#[macro_export]
macro_rules! root_subject_chunk_programme_v1 {
    ($stage:ident) => {{
        while !$stage!(completed_exact_v1) {
            $stage!(require_empty_once_v1);
            $stage!(observe_before_once_v1);
            $stage!(poll_receive_once_v1);
            $stage!(observe_subject_copy_once_v1);
            $stage!(observe_after_once_v1);
            $stage!(observe_clock_once_v1);
            $stage!(require_positive_once_v1);
            $stage!(dispose_positive_once_v1);
        }
        Ok(())
    }};
}
