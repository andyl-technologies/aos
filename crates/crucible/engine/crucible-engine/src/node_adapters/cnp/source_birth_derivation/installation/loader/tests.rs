//! Exercises actual ELF decoding and exact-name loader decisions as DATA.

use super::*;
use std::io::Write;

fn executable(dynamic: bool) -> File {
    let mut bytes = vec![0; 768];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    let machine: u16 = if cfg!(target_arch = "aarch64") {
        183
    } else {
        62
    };
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&(if dynamic { 2u16 } else { 1u16 }).to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&768u64.to_le_bytes());
    if dynamic {
        bytes[120..124].copy_from_slice(&2u32.to_le_bytes());
        bytes[128..136].copy_from_slice(&512u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&96u64.to_le_bytes());
        let strings = b"\0libborrow.so\0$ORIGIN/../lib\0child.so\0";
        bytes[384..384 + strings.len()].copy_from_slice(strings);
        for (index, (tag, value)) in [
            (5u64, 0x400180u64),
            (10, strings.len() as u64),
            (1, 1),
            (29, 14),
            (14, 29),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 512 + index * 16;
            bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
        }
    }
    let mut file = super::super::tests::temporary_file();
    file.write_all(&bytes).unwrap();
    file
}

#[test]
fn actual_original_elf_decodes_needed_soname_and_origin_paths() {
    let file = executable(true);
    let decoded = parse(
        &file,
        Path::new("/nix/store/00000000000000000000000000000000-worker/bin/worker"),
    )
    .unwrap();
    assert_eq!(decoded.needed, ["libborrow.so"]);
    assert_eq!(decoded.soname.as_deref(), Some("child.so"));
    assert_eq!(
        decoded.runpath,
        [PathBuf::from(
            "/nix/store/00000000000000000000000000000000-worker/bin/../lib"
        )]
    );
    assert!(decoded.interpreter.is_none());
}

#[test]
fn actual_static_elf_has_no_dynamic_lookup_and_partial_header_refuses() {
    let file = executable(false);
    let decoded = parse(
        &file,
        Path::new("/nix/store/00000000000000000000000000000000-worker/bin/worker"),
    )
    .unwrap();
    assert!(decoded.needed.is_empty() && decoded.soname.is_none());
    let mut partial = super::super::tests::temporary_file();
    partial.write_all(b"\x7fELF").unwrap();
    assert!(parse(&partial, Path::new("/unused")).is_err());
    assert_eq!(partial.metadata().unwrap().len(), 4);
}

#[test]
fn an_arbitrary_matching_basename_never_authenticates_a_loaded_object() {
    let mut loaded = BTreeMap::new();
    let dynamic = Dynamic {
        interpreter: None,
        soname: None,
        needed: Vec::new(),
        rpath: Vec::new(),
        runpath: Vec::new(),
    };
    remember(&mut loaded, Path::new("/foreign/libborrow.so"), &dynamic);
    assert!(!loaded.contains_key("libborrow.so"));
    assert!(expand("$ORIGIN_SUFFIX/lib", Path::new("/store/bin/main")).is_err());
    assert!(expand("$UNKNOWN/lib", Path::new("/store/bin/main")).is_err());
    assert!(expand("relative/lib", Path::new("/store/bin/main")).is_err());
}

#[test]
fn needed_tokens_refuse_before_cached_aliases_for_every_owner_origin() {
    let first = Path::new("/nix/store/00000000000000000000000000000000-first/bin/main");
    let second = Path::new("/nix/store/11111111111111111111111111111111-second/bin/main");
    let loaded = BTreeMap::from([
        (
            "$ORIGIN/libx.so".to_owned(),
            first.with_file_name("libx.so"),
        ),
        ("$LIB".to_owned(), first.with_file_name("lib64")),
        ("libx.so".to_owned(), first.with_file_name("libx.so")),
    ]);
    let entries = BTreeMap::new();

    for owner in [first, second] {
        for needed in ["$ORIGIN/libx.so", "$LIB"] {
            assert_eq!(
                select_needed(needed, owner, &loaded, &[], &entries, &[]),
                Err(RuntimeError::UnsupportedFacet)
            );
        }
        assert_eq!(
            select_needed("libx.so", owner, &loaded, &[], &entries, &[]),
            Ok(None)
        );
    }
    // The refusal is confined to DT_NEEDED; selected search-path ORIGIN
    // substitution remains available to the actual ELF parser.
    assert_eq!(
        expand("$ORIGIN/lib", first).unwrap(),
        first.parent().unwrap().join("lib")
    );
}

#[test]
fn search_refuses_cross_root_hardware_capability_directory_aliases() {
    let root = PathBuf::from("/nix/store/00000000000000000000000000000000-base");
    let other = PathBuf::from("/nix/store/11111111111111111111111111111111-other");
    let base = root.join("lib");
    let alternate = other.join("alternate");
    let alias = base.join("glibc-hwcaps/x86-64-v3");
    let library = alternate.join("libx.so");
    let content =
        crucible_node_format::canonical::content_ref(b"library", "application/octet-stream")
            .unwrap();
    let mut entries = vec![
        TreeEntry::Directory {
            path: root.clone(),
            mode: 0o555,
        },
        TreeEntry::Directory {
            path: other.clone(),
            mode: 0o555,
        },
        TreeEntry::Directory {
            path: base.clone(),
            mode: 0o555,
        },
        TreeEntry::Directory {
            path: base.join("glibc-hwcaps"),
            mode: 0o555,
        },
        TreeEntry::Directory {
            path: alternate.clone(),
            mode: 0o555,
        },
        TreeEntry::File {
            path: base.join("libx.so"),
            mode: 0o444,
            content: content.clone(),
        },
        TreeEntry::File {
            path: library.clone(),
            mode: 0o444,
            content: content.clone(),
        },
        TreeEntry::Symlink {
            path: alias.clone(),
            target: alternate,
        },
    ];
    let roots = [root.clone(), other];
    let loaded = BTreeMap::new();
    let owner = root.join("bin/main");
    {
        let roster = entries
            .iter()
            .map(|entry| (entry.path().to_path_buf(), entry))
            .collect();
        assert_eq!(
            select_needed("libx.so", &owner, &loaded, &[base.clone()], &roster, &roots),
            Err(RuntimeError::UnsupportedFacet)
        );
    }
    // The hardware-capability root can itself be a directory alias; the
    // no-follow roster then contains no lexical ISA child beneath `base`.
    let capability_root = base.join("glibc-hwcaps");
    entries.retain(|entry| entry.path() != alias && entry.path() != capability_root);
    entries.push(TreeEntry::Symlink {
        path: capability_root.clone(),
        target: roots[1].clone(),
    });
    entries.push(TreeEntry::Directory {
        path: roots[1].join("x86-64-v3"),
        mode: 0o555,
    });
    entries.push(TreeEntry::File {
        path: roots[1].join("x86-64-v3/libx.so"),
        mode: 0o444,
        content,
    });
    {
        let roster = entries
            .iter()
            .map(|entry| (entry.path().to_path_buf(), entry))
            .collect();
        assert_eq!(
            select_needed("libx.so", &owner, &loaded, &[base.clone()], &roster, &roots),
            Err(RuntimeError::UnsupportedFacet)
        );
    }

    // An ordinary file alias is not a directory search alternative. Removing
    // the hidden hwcap route leaves a genuine measured base-name selection.
    entries.retain(|entry| entry.path() != capability_root && entry.path() != base.join("libx.so"));
    entries.push(TreeEntry::Symlink {
        path: base.join("libx.so"),
        target: library.clone(),
    });
    let roster = entries
        .iter()
        .map(|entry| (entry.path().to_path_buf(), entry))
        .collect();
    assert_eq!(
        select_needed("libx.so", &owner, &loaded, &[base], &roster, &roots),
        Ok(Some(library))
    );
}
