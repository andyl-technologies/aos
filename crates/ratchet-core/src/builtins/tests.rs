//! Unit tests for the builtin registry, lookup table, and declaration metadata.

use super::declarations::{BUILTIN_LOOKUP, BUILTIN_LOOKUP_LEN};
use super::lookup::BUILTIN_LOOKUP_EMPTY_SLOT;
use super::*;
use std::collections::BTreeSet;

#[test]
fn builtin_names_are_unique() {
    let names = BUILTINS.iter().map(Builtin::name).collect::<BTreeSet<_>>();

    assert_eq!(names.len(), BUILTINS.len());
}

#[test]
fn builtin_declarations_are_sorted_for_deterministic_iteration() {
    let mut previous = None;
    for builtin in BUILTINS.iter() {
        if let Some(previous) = previous {
            assert!(
                previous < builtin.name(),
                "{} must sort before {}",
                String::from_utf8_lossy(previous),
                String::from_utf8_lossy(builtin.name())
            );
        }
        previous = Some(builtin.name());
    }
}

#[test]
fn generated_builtin_lookup_table_is_perfect_for_declared_builtins() {
    assert_eq!(BUILTINS.len(), BUILTIN_LOOKUP_LEN);
    assert_eq!(BUILTIN_LOOKUP.displacements.len(), BUILTIN_LOOKUP_LEN);
    assert_eq!(BUILTIN_LOOKUP.slots.len(), BUILTIN_LOOKUP_LEN);

    let mut seen = vec![false; BUILTIN_LOOKUP_LEN];
    for slot in BUILTIN_LOOKUP.slots {
        assert_ne!(slot, BUILTIN_LOOKUP_EMPTY_SLOT);
        let index = usize::from(slot);
        assert!(index < BUILTIN_LOOKUP_LEN, "{index}");
        assert!(!seen[index], "{index} appears more than once");
        seen[index] = true;
    }
    assert!(seen.into_iter().all(|slot| slot));

    for (expected, builtin) in BUILTINS.iter().copied().enumerate() {
        assert_eq!(
            BUILTIN_LOOKUP.candidate_index(builtin.name()),
            Some(expected)
        );
        assert_eq!(BUILTINS.lookup(builtin.name()), Some(builtin));
    }
}

#[test]
fn generated_builtin_lookup_covers_declared_builtins() {
    for builtin in BUILTINS.iter().copied() {
        assert_eq!(BUILTINS.lookup(builtin.name()), Some(builtin));
    }
    assert_eq!(BUILTINS.lookup(b""), None);
    assert_eq!(BUILTINS.lookup(b"abort\0"), None);
    assert_eq!(BUILTINS.lookup(b"toXML\0"), None);
    assert_eq!(BUILTINS.lookup(b"foldl"), None);
    assert_eq!(BUILTINS.lookup(b"zzzz"), None);
}

#[test]
fn builtin_lookup_helpers_delegate_to_registry() {
    assert!(BUILTINS.is_known_attr(b"length"));
    assert!(is_known_builtin_attr(b"length"));
    assert!(!BUILTINS.is_known_attr(b"__missing"));
    assert!(!is_known_builtin_attr(b"__missing"));
    assert_eq!(lookup_builtin(b"length"), BUILTINS.lookup(b"length"));
    assert_eq!(lookup_builtin(b"__missing"), None);
    assert_eq!(direct_builtin(b"length"), BUILTINS.direct(b"length"));
}

#[test]
fn builtin_lookup_distinguishes_top_level_names_from_attrs() {
    for name in [
        b"true".as_slice(),
        b"builtins".as_slice(),
        b"map".as_slice(),
        b"toString".as_slice(),
        b"derivationStrict".as_slice(),
    ] {
        assert!(is_unshadowable_global_name(name), "{name:?}");
        let builtin = lookup_builtin(name).expect("top-level builtin is registered");
        assert_eq!(builtin.name_scope(), BuiltinNameScope::UnshadowableGlobal);
        assert!(builtin.is_unshadowable_global());
    }
    for name in [
        b"length".as_slice(),
        b"concatMap".as_slice(),
        b"currentTime".as_slice(),
        b"storeDir".as_slice(),
    ] {
        assert!(!is_unshadowable_global_name(name), "{name:?}");
        assert!(is_known_builtin_attr(name), "{name:?}");
        let builtin = lookup_builtin(name).expect("builtin attr is registered");
        assert_eq!(builtin.name_scope(), BuiltinNameScope::BuiltinsAttrOnly);
        assert!(!builtin.is_unshadowable_global());
    }
}

#[test]
fn pinned_nix_version_matches_packaged_cpp_nix() {
    // Read `pkgs/tools/nix.nix` at runtime (not `include_str!`) and SKIP when it
    // is absent, so this test runs in a full checkout and is inert in the
    // crates-only Nix build sandbox (`pkgs.aos` uses `src = ../../../crates`,
    // which omits the repo root). The prior `include_str!("../../../../…")` was
    // a compile-time include whose path was calibrated for the full-checkout
    // layout; f8a7bb51f ("extract ratchet-core crate") moved this crate one
    // directory shallower, so the same relative path overshot to the sandbox
    // build root and failed the whole `pkgs.aos` doCheck at compile time. This
    // mirrors the runtime-read precedent in
    // aos-nix/tests/lang_conformance/upstream_tests.rs.
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(repo_root) = manifest_dir.parent().and_then(std::path::Path::parent) else {
        eprintln!(
            "no repo root above {}; skipping pinned-nix-version check",
            manifest_dir.display()
        );
        return;
    };
    let nix_nix = repo_root.join("pkgs/tools/nix.nix");
    let Ok(package) = std::fs::read_to_string(&nix_nix) else {
        eprintln!(
            "{} absent (crates-only sandbox); skipping pinned-nix-version check",
            nix_nix.display()
        );
        return;
    };
    let version = package
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let version = line.strip_prefix("version = \"")?;
            version.strip_suffix("\";")
        })
        .expect("pkgs/tools/nix.nix declares a version");

    let expected_lang_version = match version {
        "2.24.12" => 6,
        other => panic!("re-check builtins.langVersion for pinned Nix {other}"),
    };

    assert_eq!(PINNED_NIX_VERSION, version.as_bytes());
    assert_eq!(PINNED_NIX_LANG_VERSION, expected_lang_version);
}

#[test]
fn direct_builtin_declarations_mark_effectful_boundaries() {
    assert_eq!(
        direct_builtin(b"derivation"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"derivationStrict"),
        Some(BuiltinDirect::DerivationStrict)
    );
    assert_eq!(
        direct_builtin(b"getEnv"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"break"),
        Some(BuiltinDirect::LazyUnary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"hashFile"),
        Some(BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"map"),
        Some(BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"appendContext"),
        Some(BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"addErrorContext"),
        Some(BuiltinDirect::LazyStrictBinary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"match"),
        Some(BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"split"),
        Some(BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"zipAttrsWith"),
        Some(BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"genList"),
        Some(BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"sort"),
        Some(BuiltinDirect::Sort {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"pathExists"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"path"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"fetchurl"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"fetchMercurial"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"getFlake"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"readDir"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"readFile"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"readFileType"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"filterSource"),
        Some(BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"storePath"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"tryEval"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"seq"),
        Some(BuiltinDirect::StrictLazyBinary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"trace"),
        Some(BuiltinDirect::StrictLazyBinary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"traceVerbose"),
        Some(BuiltinDirect::StrictLazyBinary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"warn"),
        Some(BuiltinDirect::StrictLazyBinary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(
        direct_builtin(b"substring"),
        Some(BuiltinDirect::StrictTernary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"fromTOML"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(
        direct_builtin(b"toPath"),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Pure
        })
    );
}

#[test]
fn builtin_declarations_record_first_class_arity_by_category() {
    for name in [
        b"fetchGit".as_slice(),
        b"fetchMercurial".as_slice(),
        b"fetchTree".as_slice(),
        b"getFlake".as_slice(),
    ] {
        assert_eq!(
            BUILTINS.lookup(name).unwrap().first_class_arity(),
            Some(1),
            "{} should expose a unary first-class builtin",
            String::from_utf8_lossy(name),
        );
    }
    for name in [b"flakeRefToString".as_slice(), b"parseFlakeRef".as_slice()] {
        let builtin = BUILTINS.lookup(name).unwrap();
        assert_eq!(
            builtin.first_class_arity(),
            Some(1),
            "{} should expose a unary first-class builtin",
            String::from_utf8_lossy(name),
        );
        assert_eq!(
            builtin.direct(),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure,
            }),
            "{} should lower as a pure strict unary builtin",
            String::from_utf8_lossy(name),
        );
    }
    assert_eq!(
        BUILTINS.lookup(b"path").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS.lookup(b"fetchurl").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"filterSource")
            .unwrap()
            .first_class_arity(),
        Some(2),
    );
    assert_eq!(
        BUILTINS.lookup(b"attrNames").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS.lookup(b"getEnv").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS.lookup(b"break").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS.lookup(b"pathExists").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS.lookup(b"readFile").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS.lookup(b"tryEval").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"genericClosure")
            .unwrap()
            .first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS.lookup(b"import").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"scopedImport")
            .unwrap()
            .first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"add").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"appendContext")
            .unwrap()
            .first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"addErrorContext")
            .unwrap()
            .first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"hashFile").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"elemAt").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"elem").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"map").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"match").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"split").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"genList").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"filter").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"partition").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"concatMap").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"groupBy").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"zipAttrsWith")
            .unwrap()
            .first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"all").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"any").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"sort").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"seq").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"trace").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"traceVerbose")
            .unwrap()
            .first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"warn").unwrap().first_class_arity(),
        Some(2)
    );
    assert_eq!(
        BUILTINS.lookup(b"foldl'").unwrap().first_class_arity(),
        Some(3)
    );
    assert_eq!(
        BUILTINS.lookup(b"substring").unwrap().first_class_arity(),
        Some(3)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"replaceStrings")
            .unwrap()
            .first_class_arity(),
        Some(3)
    );
    assert_eq!(
        BUILTINS.lookup(b"derivation").unwrap().first_class_arity(),
        Some(1)
    );
    assert_eq!(
        BUILTINS
            .lookup(b"derivationStrict")
            .unwrap()
            .first_class_arity(),
        Some(1)
    );
    assert_eq!(BUILTINS.lookup(b"true").unwrap().first_class_arity(), None);
    assert_eq!(
        BUILTINS.lookup(b"fromTOML").unwrap().first_class_arity(),
        Some(1)
    );
}
