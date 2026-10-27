//! Qualifies structural mappings over actual fs-verity inodes in an ext4 guest.
//!
//! This component witness runs without capabilities. It establishes no cache
//! lease, authenticated descriptor exchange, worker sandbox or mount readiness.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{Mode, OFlags};
use terrane_format::identity::Digest;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{
    Attribute, ContentRef, Entry, EntryKind, ExtendedAttribute, LeafItem, Property, TreeUse,
};
use terrane_linux::inode_policy::InodeTable;
use terrane_linux::structural_index::{CompiledIndex, Kind, MappedIndex, MappingError};
use terrane_sdk::host::publication::VerityBinding;

#[path = "../src/inode_policy/tests/allocation.rs"]
mod allocation;

fn main() -> Result<(), Box<dyn Error>> {
    assert_eq!(rustix::process::getuid().as_raw(), 840);
    assert_eq!(rustix::process::geteuid().as_raw(), 840);
    assert_eq!(rustix::process::getgid().as_raw(), 840);
    assert_eq!(rustix::process::getegid().as_raw(), 840);
    assert!(rustix::process::getgroups()?.is_empty());
    let status = std::fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}:")))
            .ok_or("missing native capability status")?;
        assert_eq!(u64::from_str_radix(value.trim(), 16)?, 0);
    }
    assert!(status.lines().any(|line| {
        line.strip_prefix("NoNewPrivs:")
            .is_some_and(|value| value.trim() == "1")
    }));
    let root = std::env::args_os()
        .nth(1)
        .ok_or("missing ext4 scratch directory")?;
    let root = Path::new(&root);
    let path = root.join("index");
    let CompiledFixture {
        root: tree_root,
        graft: graft_root,
        compiled,
    } = compile_fixture()?;
    let bytes = compiled.bytes();
    let mut wrong_root = tree_root;
    wrong_root[0] ^= 1;
    let mut writer = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&path)?;
    compiled.write_to(&mut writer)?;
    writer.sync_all()?;
    let dummy = VerityBinding {
        algorithm: 1,
        digest: vec![0; 32],
    };

    assert!(matches!(
        MappedIndex::open(writer.try_clone()?.into(), tree_root, &dummy, 65536),
        Err(MappingError::Descriptor)
    ));
    let path_fd = rustix::fs::open(&path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?;
    assert!(matches!(
        MappedIndex::open(path_fd, tree_root, &dummy, 65536),
        Err(MappingError::Descriptor)
    ));
    assert!(matches!(
        MappedIndex::open(File::open(root)?.into(), tree_root, &dummy, 65536),
        Err(MappingError::Descriptor)
    ));
    assert!(matches!(
        MappedIndex::open(File::open(&path)?.into(), tree_root, &dummy, 65536),
        Err(MappingError::Io(_))
    ));
    drop(writer);

    let file = File::open(&path)?;
    let binding = terrane_linux::verity::enable(&file)?;
    assert_eq!(terrane_linux::verity::measure(&file)?, binding);
    compiled.verify_reader(&mut file.try_clone()?)?;
    println!("PASS: canonical compilation binds actual sealed index bytes");
    let metadata = file.metadata()?;
    let inode = metadata.ino();
    let device = metadata.dev();
    let read_fd = || -> std::io::Result<OwnedFd> { Ok(file.try_clone()?.into()) };
    assert!(matches!(
        MappedIndex::open(read_fd()?, tree_root, &binding, bytes.len() - 1),
        Err(MappingError::Limit)
    ));
    assert!(matches!(
        MappedIndex::open(read_fd()?, wrong_root, &binding, 65536),
        Err(MappingError::Root)
    ));
    assert!(matches!(
        MappedIndex::open(read_fd()?, tree_root, &dummy, 65536),
        Err(MappingError::Verity)
    ));

    let before = mappings(inode, device)?;
    let mapped = MappedIndex::open(read_fd()?, tree_root, &binding, bytes.len())?;
    assert_eq!(mappings(inode, device)?, before + 1);
    let index = mapped.index();
    assert_eq!(index.len(), 6);
    assert_eq!(
        index.lookup(b"dir/file").ok_or("file missing")?.kind(),
        Kind::File {
            content: ContentRef::Inline([3; 32]),
            size: 7,
        }
    );
    assert_eq!(
        index
            .lookup(b"other/link")
            .ok_or("link missing")?
            .governing_root()?,
        graft_root
    );
    assert_eq!(
        index
            .lookup(b"")
            .ok_or("root missing")?
            .children()?
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        [b"dir".as_slice(), b"other".as_slice()]
    );
    let file_entry = index.lookup(b"dir/file").ok_or("file missing")?;
    let alias = index
        .lookup(b"dir/hardlink")
        .ok_or("hard-link alias missing")?;
    let recorded = file_entry.metadata()?;
    assert_eq!(recorded.mode, Some(0o444));
    assert_eq!(
        recorded.attributes.get(b"uid"),
        Some(b"\x18\x2a".as_slice())
    );
    assert_eq!(
        recorded.xattrs.get(b"user.fixture"),
        Some(b"recorded\0bytes".as_slice())
    );
    assert_eq!(
        index
            .lookup(b"dir")
            .ok_or("directory missing")?
            .metadata()?
            .mode,
        Some(0o555)
    );
    assert_eq!(
        index
            .lookup(b"")
            .ok_or("root missing")?
            .metadata()?
            .root_properties
            .get(b"x.outer"),
        Some(b"\x01".as_slice())
    );
    let graft_metadata = index.lookup(b"other").ok_or("graft missing")?.metadata()?;
    assert_eq!(
        graft_metadata.root_properties.get(b"x.inner"),
        Some(b"\x02".as_slice())
    );
    assert_eq!(
        graft_metadata.graft_overrides.get(b"x.override"),
        Some(b"\x03".as_slice())
    );
    let (control, allocations) = allocation::measure(|| std::hint::black_box(vec![9u8; 128]));
    assert_eq!(control.len(), 128);
    assert!(allocations > 0);
    let mut inodes = InodeTable::with_reserved_capacity(1, 4096)?;
    let (checked, allocations) = allocation::measure(|| -> Result<(), Box<dyn Error>> {
        let alias_inode = inodes.touch_entry(alias)?;
        assert_eq!(inodes.touch_entry(file_entry)?, alias_inode);
        assert_eq!(alias_inode.1.number(), 16);
        assert_eq!(alias_inode.1.links(), 2);
        assert_eq!(inodes.len(), 1);
        for path in [b"dir".as_slice(), b"other"] {
            let directory = index.lookup(path).ok_or("directory missing")?;
            for child in directory.children()? {
                let _ = child.metadata()?;
                let _ = child.kind();
            }
            assert!(matches!(
                inodes.touch_entry(directory),
                Err(terrane_linux::inode_policy::Error::Capacity)
            ));
        }
        assert_eq!(inodes.touch_entry(alias)?, alias_inode);
        Ok(())
    });
    checked?;
    assert_eq!(allocations, 0);
    println!("PASS: mapped recorded metadata and canonical hard-link inode assignment");
    println!("PASS: reserved first-touch inode assignment and mapped metadata allocate nothing");
    assert!(OpenOptions::new().write(true).open(&path).is_err());
    assert!(file.set_len(0).is_err());

    // Replace the namespace entry while retaining the old descriptor/mapping.
    // The replacement's bytes cannot change the already mapped incarnation.
    std::fs::remove_file(&path)?;
    std::fs::write(&path, b"different unsealed incarnation")?;
    assert_ne!(std::fs::metadata(&path)?.ino(), inode);
    assert_eq!(mapped.index().root_hash(), tree_root);
    let retained_entry = mapped
        .index()
        .lookup(b"dir/hardlink")
        .ok_or("retained alias missing")?;
    assert_eq!(
        retained_entry.metadata()?.attributes.get(b"uid"),
        Some(b"\x18\x2a".as_slice())
    );
    assert_eq!(retained_entry.canonical_inode()?.path(), b"dir/file");
    assert!(matches!(
        MappedIndex::open(File::open(&path)?.into(), tree_root, &binding, 65536),
        Err(MappingError::Io(_))
    ));
    drop(mapped);
    assert_eq!(mappings(inode, device)?, before);

    let bad_path = root.join("malformed");
    std::fs::write(&bad_path, b"TRIX")?;
    let bad = File::open(&bad_path)?;
    let bad_binding = terrane_linux::verity::enable(&bad)?;
    assert!(matches!(
        MappedIndex::open(bad.into(), tree_root, &bad_binding, 65536),
        Err(MappingError::Index(_))
    ));
    println!(
        "PASS: actual sealed structural mapping, descriptor refusals, replacement custody and unmap"
    );
    Ok(())
}

struct CompiledFixture {
    root: Digest,
    graft: Digest,
    compiled: CompiledIndex,
}

fn compile_fixture() -> Result<CompiledFixture, Box<dyn Error>> {
    let graft = Tree::build(
        vec![item(
            b"link",
            EntryKind::Symlink {
                target: b"../dir/file",
            },
        )],
        Some(vec![Property {
            name: "x.inner",
            value: b"\x02",
        }]),
        4096,
        TreeUse::Ordinary,
    )?;
    let root = Tree::build(
        vec![
            item(b"dir", EntryKind::Directory { mode: 0o555 }),
            item(
                b"dir/file",
                EntryKind::File {
                    mode: 0o444,
                    size: 7,
                    content: ContentRef::Inline([3; 32]),
                    link_id: Some(b"dir/file"),
                },
            ),
            item(
                b"dir/hardlink",
                EntryKind::File {
                    mode: 0o444,
                    size: 7,
                    content: ContentRef::Inline([3; 32]),
                    link_id: Some(b"dir/file"),
                },
            ),
            item(
                b"other",
                EntryKind::Tree {
                    root: graft.root_identity(),
                    props: Some(vec![Property {
                        name: "x.override",
                        value: b"\x03",
                    }]),
                },
            ),
        ],
        Some(vec![Property {
            name: "x.outer",
            value: b"\x01",
        }]),
        4096,
        TreeUse::Ordinary,
    )?;
    let nodes: BTreeMap<_, _> = root
        .nodes()
        .chain(graft.nodes())
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect();
    let compiled = CompiledIndex::from_nodes(root.root_identity(), &nodes, 4096, 32, 65536, 65536)?;
    Ok(CompiledFixture {
        root: root.root_identity(),
        graft: graft.root_identity(),
        compiled,
    })
}

fn item(path: &[u8], kind: EntryKind<'static>) -> LeafItem<'static> {
    LeafItem {
        key: path.to_vec(),
        entry: Entry {
            kind,
            attrs: vec![Attribute {
                name: "uid",
                value: b"\x18\x2a",
            }],
            attrs_present: true,
            xattrs: vec![ExtendedAttribute {
                name: b"user.fixture",
                value: b"recorded\0bytes",
            }],
            xattrs_present: true,
            provenance: None,
        },
    }
}

fn mappings(inode: u64, device: u64) -> Result<usize, Box<dyn Error>> {
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    let expected_inode = inode.to_string();
    let expected_device = format!(
        "{:02x}:{:02x}",
        rustix::fs::major(device),
        rustix::fs::minor(device)
    );
    let mut count = 0;
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(4) == Some(&expected_inode.as_str())
            && fields.get(3) == Some(&expected_device.as_str())
        {
            assert_eq!(fields.get(1), Some(&"r--p"));
            count += 1;
        }
    }
    Ok(count)
}
