//! The ruling engine: fold reference sites into a [`Verdict`].
//!
//! Every reference edge is justified by one or more [`RefSite`]s. This
//! module reduces that evidence to a single ruling by taking the
//! *strongest* site — the rule being that one genuine runtime use keeps
//! a dependency, no matter how many spurious mentions accompany it.
//!
//! The strength ladder is deliberately conservative so the profiler does
//! not cry wolf: anything a running program could plausibly dereference
//! (a loadable ELF section, a script body, a symlink target, a bare path
//! in a config file such as a systemd unit) counts as [`Verdict::Runtime`].
//! Only references confined to dev-output files
//! ([`Verdict::DevLeak`]) or to non-loaded toolchain residue
//! ([`Verdict::Spurious`]) are reported as removable.

use serde::Serialize;

use crate::scan::{RefLocus, RefSite};

/// Relative strength of a single reference site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Strength {
    /// Non-loaded toolchain residue (comment/debug/doc/metadata).
    Spurious = 0,
    /// A reference confined to a dev-output file (`.pc`, header, `.a`).
    Dev = 1,
    /// A genuinely load-bearing runtime reference.
    Runtime = 2,
}

/// The ruling for a reference edge or a suspect path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Load-bearing at runtime — keep it.
    Runtime,
    /// Present only because a dev-output file (a `.pc`, header, libtool
    /// `.la`, or static archive) references it. The fix is to keep that
    /// dev output out of the runtime closure (split the output).
    DevLeak,
    /// Present only through non-loaded residue (an ELF `.comment`/debug
    /// section, `nix-support` metadata, documentation, or shipped
    /// source). The fix is `nuke-references`, stripping, or not shipping
    /// the file.
    Spurious,
}

impl Verdict {
    /// Returns a short human label.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Runtime => "runtime",
            Verdict::DevLeak => "dev-leak",
            Verdict::Spurious => "spurious",
        }
    }

    /// Returns true when the verdict marks the reference as removable
    /// (a [`DevLeak`](Verdict::DevLeak) or [`Spurious`](Verdict::Spurious)).
    pub fn is_leak(self) -> bool {
        !matches!(self, Verdict::Runtime)
    }

    /// Returns a one-line remediation hint for a leaking verdict.
    pub fn recommendation(self) -> &'static str {
        match self {
            Verdict::Runtime => "load-bearing; keep",
            Verdict::DevLeak => "split the dev output so it stays out of the runtime closure",
            Verdict::Spurious => "scrub with nuke-references / strip, or stop shipping the file",
        }
    }
}

/// Maps a single site to its strength.
fn site_strength(site: &RefSite) -> Strength {
    match site.locus {
        RefLocus::ElfInterp
        | RefLocus::ElfRunpath
        | RefLocus::ElfLoadable
        | RefLocus::Shebang
        | RefLocus::ScriptBody
        | RefLocus::SymlinkTarget
        | RefLocus::PlainData => Strength::Runtime,
        RefLocus::PkgConfig
        | RefLocus::LibtoolLa
        | RefLocus::ConfigScript
        | RefLocus::Header
        | RefLocus::StaticArchive => Strength::Dev,
        RefLocus::ElfComment
        | RefLocus::ElfDebug
        | RefLocus::NixSupport
        | RefLocus::Doc
        | RefLocus::Source => Strength::Spurious,
    }
}

/// Reduces a set of reference sites to a [`Verdict`].
///
/// Takes the strongest site: a single runtime use outranks any number of
/// spurious mentions. An empty slice (no located site) is treated as
/// [`Verdict::Runtime`], not a leak: when Nix records a reference but the
/// target's hash appears in no file content, the edge is a store-database
/// or build-graph relationship (such as the system toplevel pulling in an
/// `/etc` fragment by path), which is legitimate inclusion rather than
/// leaked residue. Only positively-located weak evidence marks a leak.
pub fn verdict(sites: &[RefSite]) -> Verdict {
    match sites.iter().map(site_strength).max() {
        Some(Strength::Runtime) | None => Verdict::Runtime,
        Some(Strength::Dev) => Verdict::DevLeak,
        Some(Strength::Spurious) => Verdict::Spurious,
    }
}

/// Returns the sites that determined the verdict — the strongest tier —
/// for display, capped at `limit` entries.
///
/// For a leaking verdict these are the offending dev/residue sites; for
/// a runtime verdict they are the load-bearing uses.
pub fn deciding_sites(sites: &[RefSite], limit: usize) -> Vec<&RefSite> {
    let Some(top) = sites.iter().map(site_strength).max() else {
        return Vec::new();
    };
    sites
        .iter()
        .filter(|s| site_strength(s) == top)
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::FileCategory;

    fn site(locus: RefLocus) -> RefSite {
        RefSite {
            file: "f".into(),
            category: FileCategory::Data,
            locus,
        }
    }

    #[test]
    fn runtime_outranks_spurious() {
        let sites = vec![site(RefLocus::ElfComment), site(RefLocus::ElfLoadable)];
        assert_eq!(verdict(&sites), Verdict::Runtime);
    }

    #[test]
    fn only_comment_is_spurious() {
        assert_eq!(verdict(&[site(RefLocus::ElfComment)]), Verdict::Spurious);
    }

    #[test]
    fn only_pkgconfig_is_dev_leak() {
        assert_eq!(verdict(&[site(RefLocus::PkgConfig)]), Verdict::DevLeak);
    }

    #[test]
    fn empty_is_runtime() {
        // No located site means a store-database/build-graph reference,
        // not a leak — do not cry wolf.
        assert_eq!(verdict(&[]), Verdict::Runtime);
    }
}
