//! Qualifies structural mappings over actual fs-verity inodes in an ext4 guest.
//!
//! This component witness runs without capabilities. It establishes no cache
//! lease, authenticated descriptor exchange, worker sandbox or mount readiness.

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{Mode, OFlags};
use terrane_format::tree_format::ContentRef;
use terrane_linux::structural_index::{Kind, MappedIndex, MappingError, Record, compile};
use terrane_sdk::host::publication::VerityBinding;

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
    let records = [
        Record {
            path: b"dir",
            kind: Kind::Directory {
                governing_root: None,
            },
        },
        Record {
            path: b"dir/file",
            kind: Kind::File {
                content: ContentRef::Inline([3; 32]),
                size: 7,
            },
        },
        Record {
            path: b"other",
            kind: Kind::Directory {
                governing_root: Some([9; 32]),
            },
        },
        Record {
            path: b"other/link",
            kind: Kind::Symlink(b"../dir/file"),
        },
    ];
    let bytes = compile([7; 32], &records, 32, 65536)?;
    let mut writer = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&path)?;
    writer.write_all(&bytes)?;
    writer.sync_all()?;
    let dummy = VerityBinding {
        algorithm: 1,
        digest: vec![0; 32],
    };

    assert!(matches!(
        MappedIndex::open(writer.try_clone()?.into(), [7; 32], &dummy, 65536),
        Err(MappingError::Descriptor)
    ));
    let path_fd = rustix::fs::open(&path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?;
    assert!(matches!(
        MappedIndex::open(path_fd, [7; 32], &dummy, 65536),
        Err(MappingError::Descriptor)
    ));
    assert!(matches!(
        MappedIndex::open(File::open(root)?.into(), [7; 32], &dummy, 65536),
        Err(MappingError::Descriptor)
    ));
    assert!(matches!(
        MappedIndex::open(File::open(&path)?.into(), [7; 32], &dummy, 65536),
        Err(MappingError::Io(_))
    ));
    drop(writer);

    let file = File::open(&path)?;
    let binding = terrane_linux::verity::enable(&file)?;
    assert_eq!(terrane_linux::verity::measure(&file)?, binding);
    let metadata = file.metadata()?;
    let inode = metadata.ino();
    let device = metadata.dev();
    let read_fd = || -> std::io::Result<OwnedFd> { Ok(file.try_clone()?.into()) };
    assert!(matches!(
        MappedIndex::open(read_fd()?, [7; 32], &binding, bytes.len() - 1),
        Err(MappingError::Limit)
    ));
    assert!(matches!(
        MappedIndex::open(read_fd()?, [8; 32], &binding, 65536),
        Err(MappingError::Root)
    ));
    assert!(matches!(
        MappedIndex::open(read_fd()?, [7; 32], &dummy, 65536),
        Err(MappingError::Verity)
    ));

    let before = mappings(inode, device)?;
    let mapped = MappedIndex::open(read_fd()?, [7; 32], &binding, bytes.len())?;
    assert_eq!(mappings(inode, device)?, before + 1);
    let index = mapped.index();
    assert_eq!(index.len(), 5);
    assert_eq!(
        index.lookup(b"dir/file").ok_or("file missing")?.kind(),
        records[1].kind
    );
    assert_eq!(
        index
            .lookup(b"other/link")
            .ok_or("link missing")?
            .governing_root()?,
        [9; 32]
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
    assert!(OpenOptions::new().write(true).open(&path).is_err());
    assert!(file.set_len(0).is_err());

    // Replace the namespace entry while retaining the old descriptor/mapping.
    // The replacement's bytes cannot change the already mapped incarnation.
    std::fs::remove_file(&path)?;
    std::fs::write(&path, b"different unsealed incarnation")?;
    assert_ne!(std::fs::metadata(&path)?.ino(), inode);
    assert_eq!(mapped.index().root_hash(), [7; 32]);
    assert!(mapped.index().lookup(b"dir/file").is_some());
    assert!(matches!(
        MappedIndex::open(File::open(&path)?.into(), [7; 32], &binding, 65536),
        Err(MappingError::Io(_))
    ));
    drop(mapped);
    assert_eq!(mappings(inode, device)?, before);

    let bad_path = root.join("malformed");
    std::fs::write(&bad_path, b"TRIX")?;
    let bad = File::open(&bad_path)?;
    let bad_binding = terrane_linux::verity::enable(&bad)?;
    assert!(matches!(
        MappedIndex::open(bad.into(), [7; 32], &bad_binding, 65536),
        Err(MappingError::Index(_))
    ));
    println!(
        "PASS: actual sealed structural mapping, descriptor refusals, replacement custody and unmap"
    );
    Ok(())
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
