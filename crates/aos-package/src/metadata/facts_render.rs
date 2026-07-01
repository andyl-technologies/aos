//! Render normalized [`Facts`] into the `host-facts.nix` module.
//!
//! Facts enter eval **only** as typed `host.facts.*` declared inputs (D9),
//! keeping eval a pure function of `(modules + host.nix + facts)`. Stage-2
//! renders `/run/aos-eval/host-facts.nix` from `facts.json`; this module is
//! that pure, deterministic rendering.
//!
//! ```nix
//! # /run/aos-eval/host-facts.nix — rendered, not operator-authored.
//! {
//!   host.facts = {
//!     hostname = "ip-10-0-1-22";
//!     instanceId = "i-0abc…";
//!     region = "us-east-1";
//!     availabilityZone = "us-east-1a";
//!     sshAuthorizedKeys = [ "ssh-ed25519 AAAA… op@host" ];
//!     macToIface = [ { mac = "0a:1b:…"; iface = "ens5"; } ];
//!     diskIds = [ "nvme-Amazon_Elastic_Block_Store_vol0abc" ];
//!   };
//! }
//! ```
//!
//! Only set fields are emitted, so the output is stable across boots for a
//! fixed input. Strings are escaped for the Nix `"…"` literal; no fact value
//! is ever interpreted as a security decision (review M-gen0key) — the
//! renderer is pure text.

use super::fetcher::Facts;

/// Escape a string for a Nix double-quoted literal.
///
/// Escapes `\`, `"`, `$` (to neutralize `${…}` antiquotation), and the common
/// control characters. Facts are untrusted, so this must be airtight against a
/// hostile hostname or key comment breaking out of the literal.
fn nix_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a single `name = "value";` line at the given indent if `value` is set.
fn opt_str_line(out: &mut String, indent: &str, name: &str, value: &Option<String>) {
    if let Some(v) = value {
        out.push_str(&format!("{indent}{name} = \"{}\";\n", nix_escape(v)));
    }
}

/// Render a Nix list-of-strings literal (`[ "a" "b" ]`).
fn nix_str_list(values: &[String]) -> String {
    if values.is_empty() {
        return "[ ]".to_string();
    }
    let items: Vec<String> = values.iter().map(|v| format!("\"{}\"", nix_escape(v))).collect();
    format!("[ {} ]", items.join(" "))
}

/// Render [`Facts`] into the `host-facts.nix` source text.
///
/// The output is a self-contained module setting `host.facts.*`. Empty
/// collections and unset scalars are omitted; an entirely-empty [`Facts`]
/// renders an empty `host.facts = { };`. The rendering is deterministic — the
/// same input always yields byte-identical output — so it can feed the
/// `facts_hash` contract directly.
pub fn render_host_facts_nix(facts: &Facts) -> String {
    let mut out = String::new();
    out.push_str("# /run/aos-eval/host-facts.nix — rendered from facts.json, not operator-authored.\n");
    out.push_str("{\n");
    out.push_str("  host.facts = {\n");

    let ind = "    ";
    opt_str_line(&mut out, ind, "hostname", &facts.hostname);
    opt_str_line(&mut out, ind, "instanceId", &facts.instance_id);
    opt_str_line(&mut out, ind, "region", &facts.region);
    opt_str_line(&mut out, ind, "availabilityZone", &facts.availability_zone);

    if !facts.ssh_authorized_keys.is_empty() {
        out.push_str(&format!(
            "{ind}sshAuthorizedKeys = {};\n",
            nix_str_list(&facts.ssh_authorized_keys)
        ));
    }

    if !facts.mac_to_iface.is_empty() {
        out.push_str(&format!("{ind}macToIface = [\n"));
        for m in &facts.mac_to_iface {
            out.push_str(&format!(
                "{ind}  {{ mac = \"{}\"; iface = \"{}\"; }}\n",
                nix_escape(&m.mac),
                nix_escape(&m.iface)
            ));
        }
        out.push_str(&format!("{ind}];\n"));
    }

    if !facts.disk_ids.is_empty() {
        out.push_str(&format!("{ind}diskIds = {};\n", nix_str_list(&facts.disk_ids)));
    }

    out.push_str("  };\n");
    out.push_str("}\n");
    out
}
