//! Opt-in end-of-engine JIT and compiled-body cache diagnostics.

use super::NixJitTier1Engine;

impl Drop for NixJitTier1Engine {
    /// Dumps JIT histograms and persistent compiled-body counters when enabled.
    fn drop(&mut self) {
        if std::env::var("AOS_NIX_EVAL_STATS").as_deref() != Ok("1") {
            return;
        }
        dump_u32_histogram(
            "aos_nix_tier1_blacklist_histogram",
            self.blacklist_histogram(),
        );
        dump_u64_histogram(
            "aos_nix_tier1_dispatched_histogram",
            self.dispatched_histogram(),
        );
        dump_u32_histogram("aos_nix_tier1_gated_histogram", self.gated_histogram());

        let gated_cost = self.gated_cost_histogram();
        if !gated_cost.is_empty() {
            let native = gated_cost
                .iter()
                .map(|(native, count)| format!("\"{native}\":{count}"))
                .collect::<Vec<_>>()
                .join(",");
            eprintln!(
                "{{\"aos_nix_tier1_gated_cost_histogram\":\
                 {{\"lowerable\":{},\"unlowerable\":{},\"native_insts\":{{{native}}}}}}}",
                self.gated_lowerable_count(),
                self.gated_unlowerable_count(),
            );
        }
        dump_u32_histogram(
            "aos_nix_tier1_interp_shape_histogram",
            self.interp_shape_histogram(),
        );
        dump_u32_histogram(
            "aos_nix_tier1_interp_child_kind_histogram",
            self.interp_child_kind_histogram(),
        );

        if let Some(cache) = self.tier2.get_mut().compiled_cache.as_ref() {
            eprintln!("{}", cache.stats().to_json());
        }
    }
}

fn dump_u32_histogram(name: &str, entries: Vec<(String, u32)>) {
    dump_histogram(
        name,
        entries
            .into_iter()
            .map(|(key, value)| (key, u64::from(value))),
    );
}

fn dump_u64_histogram(name: &str, entries: Vec<(String, u64)>) {
    dump_histogram(name, entries);
}

fn dump_histogram(name: &str, entries: impl IntoIterator<Item = (String, u64)>) {
    let body = entries
        .into_iter()
        .map(|(key, value)| format!("\"{key}\":{value}"))
        .collect::<Vec<_>>()
        .join(",");
    if !body.is_empty() {
        eprintln!("{{\"{name}\":{{{body}}}}}");
    }
}
