//! File and reference-site classification taxonomy.
//!
//! Two enums drive the verdict engine:
//!
//! - [`FileCategory`] — what *kind* of file a reference was found in
//!   (a shared library, a header, a `pkg-config` file, documentation,
//!   …), derived from the path and a content sniff.
//! - [`RefLocus`] — *where inside* that file the reference string sits
//!   (an ELF `.interp`, an RPATH entry, a `.comment` section, a shebang,
//!   plain data, …). The locus is what separates a load-bearing
//!   reference from a spurious leftover.

use serde::Serialize;

/// The kind of file a reference was discovered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileCategory {
    /// An ELF executable (`ET_EXEC` or `ET_DYN` with an entry point in
    /// a `bin`/`libexec`-style location).
    ElfExecutable,
    /// An ELF shared object (`lib*.so*`).
    SharedLib,
    /// A static archive (`.a`) — a build/link-time artifact.
    StaticLib,
    /// A C/C++ header (`include/**.h`).
    Header,
    /// A `pkg-config` `.pc` file.
    PkgConfig,
    /// A libtool `.la` archive descriptor — a notorious reference leaker.
    LibtoolLa,
    /// A `*-config` helper script (`pkg-config`-era build helper).
    ConfigScript,
    /// An interpreted script with a `#!` shebang.
    Script,
    /// Compiled locale data (`share/locale/**`).
    Locale,
    /// Documentation, man pages, or info pages (`share/{doc,man,info,gtk-doc}`).
    Doc,
    /// Split or embedded debug information.
    DebugInfo,
    /// Source text (`.c`, `.h`, `.py`, …) shipped into the output.
    Source,
    /// A kernel module (`lib/modules/**.ko`).
    KernelModule,
    /// A Nix bookkeeping file (`nix-support/**`).
    NixSupport,
    /// A symlink whose target string carries the reference.
    Symlink,
    /// Anything else (config data, resources, unknown binaries).
    Data,
}

/// Where, within a file, a reference string was located.
///
/// Ordered loosely from strongest (genuinely load-bearing) to weakest
/// (almost certainly spurious). The verdict engine maps each locus —
/// together with the [`FileCategory`] — to a strength in
/// [`verdict`](crate::verdict).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefLocus {
    /// The ELF `.interp` section — the dynamic linker. Always real.
    ElfInterp,
    /// An ELF `DT_RPATH`/`DT_RUNPATH` entry. Real runtime search path.
    ElfRunpath,
    /// A loadable ELF section (`.rodata`, `.data`, `.text`, …): a string
    /// the running binary can dereference (e.g. a `dlopen`/`execve`
    /// path). Treated as real, though some are baked-in but unused.
    ElfLoadable,
    /// An ELF `.comment`/`.note` section — compiler/toolchain stamp.
    /// Not loaded at runtime.
    ElfComment,
    /// An ELF `.debug_*`, `.symtab`, or `.strtab` section — debug info.
    /// Not loaded at runtime; should be split or stripped.
    ElfDebug,
    /// The `#!` shebang line of a script. The interpreter is real.
    Shebang,
    /// The body of a script (a path the script invokes). Real.
    ScriptBody,
    /// The target of a symlink. Real (the link resolves into the dep).
    SymlinkTarget,
    /// Inside a `pkg-config` `.pc` file — dev-only.
    PkgConfig,
    /// Inside a libtool `.la` file — dev-only.
    LibtoolLa,
    /// Inside a `*-config` helper script — dev-only.
    ConfigScript,
    /// Inside a header — dev-only.
    Header,
    /// Inside a static archive — dev/link-time only.
    StaticArchive,
    /// Inside a `nix-support/**` bookkeeping file — spurious.
    NixSupport,
    /// Inside documentation/man/info — spurious.
    Doc,
    /// Inside shipped source text — spurious.
    Source,
    /// A bare string in an unclassified data file.
    PlainData,
}

impl RefLocus {
    /// Returns a short human label for tables and prose.
    pub fn label(self) -> &'static str {
        match self {
            RefLocus::ElfInterp => "ELF .interp (dynamic linker)",
            RefLocus::ElfRunpath => "ELF RPATH/RUNPATH",
            RefLocus::ElfLoadable => "ELF loadable section",
            RefLocus::ElfComment => "ELF .comment/.note",
            RefLocus::ElfDebug => "ELF debug/symtab",
            RefLocus::Shebang => "script shebang",
            RefLocus::ScriptBody => "script body",
            RefLocus::SymlinkTarget => "symlink target",
            RefLocus::PkgConfig => "pkg-config .pc",
            RefLocus::LibtoolLa => "libtool .la",
            RefLocus::ConfigScript => "*-config script",
            RefLocus::Header => "C/C++ header",
            RefLocus::StaticArchive => "static archive .a",
            RefLocus::NixSupport => "nix-support metadata",
            RefLocus::Doc => "documentation",
            RefLocus::Source => "source text",
            RefLocus::PlainData => "plain data",
        }
    }
}

/// Splits a store path into its `(hash, name)` components.
///
/// A store path basename has the form `<32-char-hash>-<name>`. Returns
/// `None` if `path`'s basename is too short to carry a hash.
///
/// # Examples
///
/// ```no_run
/// use aos_profile::scan::classify::split_store_path;
///
/// let (hash, name) =
///     split_store_path("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-jq-1.7").unwrap();
/// assert_eq!(hash, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
/// assert_eq!(name, "jq-1.7");
/// ```
pub fn split_store_path(path: &str) -> Option<(&str, &str)> {
    let base = path.rsplit('/').next().unwrap_or(path);
    if base.len() < 33 || base.as_bytes().get(32) != Some(&b'-') {
        return None;
    }
    Some((&base[..32], &base[33..]))
}

/// Returns the 32-character store hash of `path`, if present.
pub fn store_hash(path: &str) -> Option<&str> {
    split_store_path(path).map(|(h, _)| h)
}

/// Returns the human-readable name component of a store `path`.
///
/// Falls back to the whole basename when the path does not carry a
/// recognisable store hash.
pub fn store_name(path: &str) -> &str {
    split_store_path(path)
        .map(|(_, n)| n)
        .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path))
}

/// Classifies a file by its store-relative path and a small content
/// prefix, independent of any reference it may contain.
///
/// `rel` is the path relative to the owning store path (e.g.
/// `lib/pkgconfig/zlib.pc`). `head` is the first few bytes of the file
/// (used only to recognise shebangs); pass an empty slice for symlinks
/// or when content is unavailable.
pub fn classify_file(rel: &str, head: &[u8]) -> FileCategory {
    let lower = rel.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);

    if lower.starts_with("nix-support/") || lower.contains("/nix-support/") {
        return FileCategory::NixSupport;
    }
    if base.ends_with(".pc") {
        return FileCategory::PkgConfig;
    }
    if base.ends_with(".la") {
        return FileCategory::LibtoolLa;
    }
    if base.ends_with(".a") {
        return FileCategory::StaticLib;
    }
    if base.ends_with(".ko") || lower.contains("/lib/modules/") {
        return FileCategory::KernelModule;
    }
    if lower.contains("/include/") || base.ends_with(".h") || base.ends_with(".hpp") {
        return FileCategory::Header;
    }
    if lower.contains("/share/locale/") {
        return FileCategory::Locale;
    }
    if lower.contains("/share/man/")
        || lower.contains("/share/doc/")
        || lower.contains("/share/info/")
        || lower.contains("/share/gtk-doc/")
    {
        return FileCategory::Doc;
    }
    if base.ends_with(".c") || base.ends_with(".cc") || base.ends_with(".cpp") {
        return FileCategory::Source;
    }
    if base.ends_with(".debug") {
        return FileCategory::DebugInfo;
    }
    if base.ends_with("-config") {
        return FileCategory::ConfigScript;
    }
    if head.starts_with(b"#!") {
        return FileCategory::Script;
    }
    FileCategory::Data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_store_paths() {
        assert_eq!(
            split_store_path("/nix/store/00000000000000000000000000000000-bash-5.2"),
            Some(("00000000000000000000000000000000", "bash-5.2")),
        );
        assert_eq!(split_store_path("/nix/store/short-x"), None);
    }

    #[test]
    fn classifies_common_files() {
        assert_eq!(
            classify_file("lib/pkgconfig/zlib.pc", b""),
            FileCategory::PkgConfig
        );
        assert_eq!(
            classify_file("nix-support/propagated-build-inputs", b""),
            FileCategory::NixSupport
        );
        assert_eq!(classify_file("include/zlib.h", b""), FileCategory::Header);
        assert_eq!(classify_file("bin/foo", b"#!/bin"), FileCategory::Script);
        assert_eq!(classify_file("bin/foo", b"\x7fELF"), FileCategory::Data);
    }
}
