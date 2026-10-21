//! Shares the actual native semantic append schedule at compile time.
//!
//! Real role owners retain their private contexts, semantic restrictions and
//! genuine final typed loans. The recipe owns no writer, lender or acceptance
//! result and defines no authority trait, callback or supplied-parts constructor.
//! Its named lexical stages expand in place, without extra closure captures or
//! scopes. Returned append errors and independent owed native posts retain the
//! same first-cause and guard/stage disposal order as the original schedule.

/// Runs the existing append schedule inside the real role's private context.
///
/// The `ordinary,` form is for an actual ordinary-only owner. Its lexical
/// expansion never references a selected finisher or disposition selector.
/// The original form keeps the exact existing mixed-owner expansion. Neither
/// form constructs an owner, selects a runtime mode or grants a role loan.
///
/// The role supplies its existing preflight checks, actual final typed crossing,
/// optional durable-failure check and post-publication bookkeeping as lexical
/// source. Those blocks create neither callbacks nor replacement role gates.
/// All seven names are actual local bindings, so the expansion introduces no
/// additional owned carrier, native observation or payment frontier. The full
/// context/stage/return representations must already be priced by the genuine
/// caller before native entry; this recipe grants no funding or authority.
///
/// `final_crossing` follows slow native preparation and the retained cache hold,
/// immediately before append. The complete primary result is parked before
/// selected native finishing, and the cache guard drops before the ordinary
/// native stage. An entered failure follows the same independently owed finish.
#[macro_export]
macro_rules! run_canonical_semantic_append_v1 {
    (
        context: $context:ident,
        transaction: $transaction:ident,
        gate: $cache_gate:ident,
        boundary: $boundary:expr,
        coordinates: ($materialized_bytes:ident, $commit_sequence:ident,
                      $following_sequence:ident, $durable_bytes:ident),
        preflight: { $($preflight:tt)* },
        final_crossing: { $($final_crossing:tt)* },
        durable_check: { $($durable_check:tt)* },
        published: { $($published:tt)* },
        completed: { $($completed:tt)* },
    ) => {
        $crate::run_canonical_semantic_append_v1!(@body mixed;
            context: $context,
            transaction: $transaction,
            gate: $cache_gate,
            boundary: $boundary,
            coordinates: ($materialized_bytes, $commit_sequence, $following_sequence, $durable_bytes),
            preflight: { $($preflight)* },
            final_crossing: { $($final_crossing)* },
            durable_check: { $($durable_check)* },
            published: { $($published)* },
            completed: { $($completed)* },
        )
    };
    (ordinary,
        context: $context:ident,
        transaction: $transaction:ident,
        gate: $cache_gate:ident,
        boundary: $boundary:expr,
        coordinates: ($materialized_bytes:ident, $commit_sequence:ident,
                      $following_sequence:ident, $durable_bytes:ident),
        preflight: { $($preflight:tt)* },
        final_crossing: { $($final_crossing:tt)* },
        durable_check: { $($durable_check:tt)* },
        published: { $($published:tt)* },
        completed: { $($completed:tt)* },
    ) => {
        $crate::run_canonical_semantic_append_v1!(@body ordinary;
            context: $context,
            transaction: $transaction,
            gate: $cache_gate,
            boundary: $boundary,
            coordinates: ($materialized_bytes, $commit_sequence, $following_sequence, $durable_bytes),
            preflight: { $($preflight)* },
            final_crossing: { $($final_crossing)* },
            durable_check: { $($durable_check)* },
            published: { $($published)* },
            completed: { $($completed)* },
        )
    };
    (@body $disposition:ident;
        context: $context:ident,
        transaction: $transaction:ident,
        gate: $cache_gate:ident,
        boundary: $boundary:expr,
        coordinates: ($materialized_bytes:ident, $commit_sequence:ident,
                      $following_sequence:ident, $durable_bytes:ident),
        preflight: { $($preflight:tt)* },
        final_crossing: { $($final_crossing:tt)* },
        durable_check: { $($durable_check:tt)* },
        published: { $($published:tt)* },
        completed: { $($completed:tt)* },
    ) => {{
        let mut cache_policy_guard = None;
        let primary = (|| {
            $context.prepare($transaction)?;
            let $materialized_bytes = $context.projected_materialized_bytes()
                .ok_or($boundary)?;
            let ($commit_sequence, $following_sequence) = $context.coordinates()?;
            $($preflight)*

            // Retain the hold-journal lock through the durable append. The freeze
            // writer takes Cache journal locks before this lock in the same order.
            cache_policy_guard = Some($context.before_cache_append(&mut $cache_gate)?);

            $($final_crossing)*
            let $durable_bytes = $context.append()?;

            $($durable_check)*

            while $context.apply_next_record()? {}
            $context.publish()?;

            $($published)*

            if let Err(error) =
                $context.own_cache_successor(&mut $cache_gate, $transaction, $following_sequence, $durable_bytes)
            {
                $context.poison();
                return Err(error);
            }

            $crate::run_canonical_semantic_append_v1!(@positive $disposition; $context);
            $($completed)*

        })();

        $crate::run_canonical_semantic_append_v1!(
            @selected $disposition; $context, primary, cache_policy_guard
        );
        // The ordinary cache guard still drops before the native stage, and
        // only after the original positive finish or original error frontier.
        drop(cache_policy_guard);
        $context.drop_stage();
        primary
    }};
    (@positive mixed; $context:ident) => {
        if $context.is_ordinary() {
            $context.finish_ordinary()?;
        }
    };
    (@positive ordinary; $context:ident) => {
        $context.finish_ordinary()?;
    };
    (@selected mixed; $context:ident, $primary:ident, $guard:ident) => {
        #[cfg(target_os = "linux")]
        if !$context.is_ordinary() {
            let result = $context.finish_selected($primary);
            drop($guard);
            return result;
        }
    };
    (@selected ordinary; $context:ident, $primary:ident, $guard:ident) => {};
}
