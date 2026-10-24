//! Checks composed metadata behavior and refusal before permanent inode assignment.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::structural_index::{self, Record};

fn node(entry: Entry<'_>) -> u64 {
    inode_policy::NodeIdentity::new(entry.governing_root().unwrap(), entry.path())
        .unwrap()
        .node_id()
}

fn bytes() -> Vec<u8> {
    structural_index::compile(
        [7; 32],
        &[
            Record {
                path: b"dir",
                kind: Kind::Directory {
                    governing_root: None,
                },
            },
            Record {
                path: b"dir/link\xff",
                kind: Kind::Symlink(b"../raw\xff"),
            },
        ],
        3,
        4096,
    )
    .unwrap()
}

fn metadata(index: Index<'_>, cache: CachePolicy, xattrs: XattrPolicy) -> Metadata<'_> {
    let mut metadata = Metadata::new(
        index,
        Limits {
            namespace_entries: 3,
            namespace_bytes: 4096,
            inodes: 3,
            inode_bytes: 4096,
        },
        cache,
        xattrs,
    )
    .unwrap();
    // These codec fixtures address nodes directly. The production constructor
    // starts with root alone; its LOOKUP-driven behavior is tested separately.
    for position in 0..index.len() {
        metadata.namespace.remember(position).unwrap();
    }
    metadata
}

fn record(opcode: u32, node: u64, body: &[u8]) -> Vec<u8> {
    let mut record = vec![0; 40];
    record.extend_from_slice(body);
    let length = record.len() as u32;
    record[..4].copy_from_slice(&length.to_ne_bytes());
    record[4..8].copy_from_slice(&opcode.to_ne_bytes());
    record[8..16].copy_from_slice(&1u64.to_ne_bytes());
    record[16..24].copy_from_slice(&node.to_ne_bytes());
    record
}

fn request(record: &[u8]) -> Request<'_> {
    Request::parse(record, 4096).unwrap()
}

fn payload(response: Response<'_>) -> &[u8] {
    match response {
        Response::Payload(bytes) => bytes,
        other => panic!("expected payload, got {other:?}"),
    }
}

#[test]
fn raw_lookup_getattr_and_readlink_share_one_original_namespace() {
    let bytes = bytes();
    let index = Index::open(&bytes).unwrap();
    let mut metadata = metadata(index, CachePolicy::Pinned, XattrPolicy::Recorded);
    let dir = node(index.lookup(b"dir").unwrap());
    let link = node(index.lookup(b"dir/link\xff").unwrap());
    let mut scratch = [0xaa; 256];

    let lookup = record(1, dir, b"link\xff\0");
    let encoded = payload(
        metadata
            .dispatch(request(&lookup), |_| Presentation::default(), &mut scratch)
            .unwrap(),
    );
    assert_eq!(u64::from_ne_bytes(encoded[..8].try_into().unwrap()), link);
    let inode = u64::from_ne_bytes(encoded[40..48].try_into().unwrap());
    let getattr = record(3, link, &[0; 16]);
    let encoded = payload(
        metadata
            .dispatch(request(&getattr), |_| Presentation::default(), &mut scratch)
            .unwrap(),
    );
    assert_eq!(
        u64::from_ne_bytes(encoded[16..24].try_into().unwrap()),
        inode
    );
    let readlink = record(5, link, &[]);
    assert_eq!(
        payload(
            metadata
                .dispatch(
                    request(&readlink),
                    |_| Presentation::default(),
                    &mut scratch
                )
                .unwrap()
        ),
        b"../raw\xff"
    );
    assert_eq!(metadata.inodes.len(), 1);
    assert_eq!(metadata.entry(link).unwrap().path(), b"dir/link\xff");
}

#[test]
fn malformed_supported_requests_never_assign_inodes_or_change_scratch() {
    let bytes = bytes();
    let index = Index::open(&bytes).unwrap();
    let mut metadata = metadata(index, CachePolicy::Pinned, XattrPolicy::Recorded);
    let mut directory = [0; 40];
    directory[..8].copy_from_slice(&1u64.to_ne_bytes());
    directory[36] = 1;
    let mut flags = [0; 16];
    flags[0] = 2;
    let mut zero_unique = record(1, 1, b"dir\0");
    zero_unique[8..16].fill(0);
    let records = [
        record(1, 1, b"dir"),
        record(3, 1, &[0; 15]),
        record(3, 1, &flags),
        record(5, 1, &[0]),
        record(22, 1, &[0; 8]),
        record(23, 1, &[0; 9]),
        record(28, 1, &[0; 40]),
        record(28, 1, &directory),
        zero_unique,
    ];

    for record in records {
        let mut scratch = [0xaa; 256];
        assert!(matches!(
            metadata.dispatch(request(&record), |_| Presentation::default(), &mut scratch),
            Err(Error::Protocol(_))
        ));
        assert!(metadata.inodes.is_empty());
        assert_eq!(scratch, [0xaa; 256]);
    }
}

#[test]
fn operation_errnos_and_unhandled_records_preserve_permanent_state() {
    let bytes = bytes();
    let index = Index::open(&bytes).unwrap();
    let mut metadata = metadata(index, CachePolicy::Revalidate, XattrPolicy::Recorded);
    let link = node(index.lookup(b"dir/link\xff").unwrap());
    let mut scratch = [0xaa; 256];
    for (record, errno) in [
        (record(3, u64::MAX, &[0; 16]), libc::ESTALE),
        (record(1, link, b"child\0"), libc::ENOTDIR),
        (record(5, 1, &[]), libc::EINVAL),
    ] {
        assert!(
            matches!(metadata.dispatch(request(&record), |_| panic!("errno must not resolve presentation"), &mut scratch).unwrap(), Response::Errno(actual) if actual == errno)
        );
    }
    for opcode in [2, 15, 42, u32::MAX] {
        let mut record = record(opcode, u64::MAX, &[]);
        record[8..16].fill(0);
        assert!(matches!(
            metadata
                .dispatch(
                    request(&record),
                    |_| panic!("unhandled operation"),
                    &mut scratch
                )
                .unwrap(),
            Response::Unhandled
        ));
    }
    assert!(metadata.inodes.is_empty());
    assert_eq!(scratch, [0xaa; 256]);
}

#[test]
fn absence_and_xattr_policy_remain_distinct_from_protocol_faults() {
    let bytes = bytes();
    let index = Index::open(&bytes).unwrap();
    let mut get = vec![0; 8];
    get.extend_from_slice(b"user.missing\0");
    let get = record(22, 1, &get);
    let list = record(23, 1, &[0; 8]);
    let absent = record(1, 1, b"absent\0");

    for (cache, policy, errno, ttl) in [
        (
            CachePolicy::Pinned,
            XattrPolicy::Recorded,
            libc::ENODATA,
            u64::MAX,
        ),
        (
            CachePolicy::Revalidate,
            XattrPolicy::Disabled,
            libc::EOPNOTSUPP,
            0,
        ),
    ] {
        let mut metadata = metadata(index, cache, policy);
        let mut scratch = [0xaa; 256];
        assert!(
            matches!(metadata.dispatch(request(&get), |_| Presentation::default(), &mut scratch).unwrap(), Response::Errno(actual) if actual == errno)
        );
        let response = metadata
            .dispatch(request(&list), |_| Presentation::default(), &mut scratch)
            .unwrap();
        if policy == XattrPolicy::Recorded {
            assert_eq!(payload(response), &[0; 8]);
        } else {
            assert!(matches!(response, Response::Errno(libc::EOPNOTSUPP)));
        }
        let encoded = payload(
            metadata
                .dispatch(
                    request(&absent),
                    |_| panic!("absent lookup has no presentation"),
                    &mut scratch,
                )
                .unwrap(),
        );
        assert_eq!(encoded.len(), 128);
        assert_eq!(u64::from_ne_bytes(encoded[..8].try_into().unwrap()), 0);
        assert_eq!(u64::from_ne_bytes(encoded[16..24].try_into().unwrap()), ttl);
        assert!(metadata.inodes.is_empty());
    }
}

#[test]
fn directory_pages_obey_original_handles_cookies_and_complete_record_bounds() {
    let bytes = bytes();
    let index = Index::open(&bytes).unwrap();
    let mut metadata = metadata(index, CachePolicy::Pinned, XattrPolicy::Recorded);
    let mut read = [0; 40];
    // Handle identity is independent of its original canonical node.
    read[..8].copy_from_slice(&42u64.to_ne_bytes());
    read[16..20].copy_from_slice(&32u32.to_ne_bytes());
    let mut scratch = [0xaa; 256];

    let page = record(28, 1, &read);
    let encoded = payload(
        metadata
            .dispatch(
                request(&page),
                |_| panic!("directory page resolves no presentation"),
                &mut scratch,
            )
            .unwrap(),
    );
    assert_eq!(encoded.len(), 32);
    assert_eq!(u64::from_ne_bytes(encoded[8..16].try_into().unwrap()), 1);
    assert_eq!(encoded[24], b'.');
    assert_eq!(scratch[32..], [0xaa; 224]);
    assert_eq!(metadata.inodes.len(), 1);

    read[8..16].copy_from_slice(&u64::MAX.to_ne_bytes());
    let end = record(28, 1, &read);
    assert!(
        payload(
            metadata
                .dispatch(request(&end), |_| Presentation::default(), &mut scratch)
                .unwrap()
        )
        .is_empty()
    );
    read[8..16].fill(0);
    read[16..20].copy_from_slice(&31u32.to_ne_bytes());
    let short = record(28, 1, &read);
    assert!(matches!(
        metadata.dispatch(request(&short), |_| Presentation::default(), &mut scratch),
        Err(Error::Directory(fuse_directory::Error::BufferTooSmall))
    ));
    assert_eq!(metadata.inodes.len(), 1);
}

#[test]
fn worker_lookup_retains_only_touched_nodes_and_faults_at_the_original_bound() {
    let bytes = bytes();
    let index = Index::open(&bytes).unwrap();
    let mut metadata = Metadata::new(
        index,
        Limits {
            namespace_entries: 2,
            namespace_bytes: 4096,
            inodes: 3,
            inode_bytes: 4096,
        },
        CachePolicy::Pinned,
        XattrPolicy::Recorded,
    )
    .unwrap();
    let directory = node(index.lookup(b"dir").unwrap());
    let link = node(index.lookup(b"dir/link\xff").unwrap());
    let mut scratch = [0; 256];
    assert!(metadata.entry(directory).is_none());
    let getattr = record(3, directory, &[0; 16]);
    assert!(matches!(
        metadata
            .dispatch(request(&getattr), |_| Presentation::default(), &mut scratch)
            .unwrap(),
        Response::Errno(libc::ESTALE)
    ));
    assert!(metadata.inodes.is_empty());

    let lookup = record(1, 1, b"dir\0");
    let encoded = payload(
        metadata
            .dispatch(request(&lookup), |_| Presentation::default(), &mut scratch)
            .unwrap(),
    );
    assert_eq!(
        u64::from_ne_bytes(encoded[..8].try_into().unwrap()),
        directory
    );
    assert_eq!(metadata.entry(directory).unwrap().path(), b"dir");
    assert!(metadata.entry(link).is_none());
    let missing = record(1, directory, b"missing\0");
    payload(
        metadata
            .dispatch(request(&missing), |_| Presentation::default(), &mut scratch)
            .unwrap(),
    );
    assert_eq!(metadata.inodes.len(), 1);

    let child = record(1, directory, b"link\xff\0");
    assert!(matches!(
        metadata.dispatch(request(&child), |_| Presentation::default(), &mut scratch),
        Err(Error::Namespace(fuse_namespace::Error::Budget))
    ));
    assert!(metadata.entry(link).is_none());
    assert_eq!(metadata.entry(directory).unwrap().path(), b"dir");
    assert_eq!(metadata.entry(1).unwrap().path(), b"");
}
