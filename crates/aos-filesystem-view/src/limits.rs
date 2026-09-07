//! Hard limits for portable-tree compilation.

/// Bounds every graph-wide input and retained compiler resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeCompileLimits {
    /// Maximum encoded bytes in one portable object.
    pub object_bytes: usize,
    /// Maximum expanded filesystem nodes.
    pub nodes: u64,
    /// Maximum entries in one directory.
    pub directory_entries: u64,
    /// Maximum expanded directory depth, with the root at zero.
    pub depth: u32,
    /// Maximum aggregate component-name bytes.
    pub name_bytes: u64,
    /// Maximum aggregate symbolic-link target bytes.
    pub symlink_bytes: u64,
    /// Maximum aggregate extended-attribute name and value bytes.
    pub xattr_bytes: u64,
    /// Maximum aggregate extended-attribute entries.
    pub xattrs: u64,
    /// Maximum aggregate ACL entries.
    pub acl_entries: u64,
    /// Maximum aggregate sparse extents.
    pub extents: u64,
    /// Maximum distinct hard-link groups.
    pub hardlink_groups: u64,
    /// Maximum aggregate hard-link members.
    pub hardlink_members: u64,
    /// Maximum aggregate logical file bytes, counting expanded paths.
    pub logical_bytes: u64,
    /// Maximum bytes retained in the explicit graph work queue.
    pub working_bytes: u64,
    /// Maximum encoded structural-index bytes.
    pub index_bytes: u64,
    /// Maximum temporary bytes for one encoded structural-index record.
    pub index_record_bytes: u64,
}

impl Default for TreeCompileLimits {
    fn default() -> Self {
        Self {
            object_bytes: 64 * 1024 * 1024,
            nodes: 1_048_576,
            directory_entries: 1_048_576,
            depth: 4_096,
            name_bytes: 256 * 1024 * 1024,
            symlink_bytes: 64 * 1024 * 1024,
            xattr_bytes: 256 * 1024 * 1024,
            xattrs: 4_194_304,
            acl_entries: 4_194_304,
            extents: 4_194_304,
            hardlink_groups: 1_048_576,
            hardlink_members: 1_048_576,
            logical_bytes: u64::MAX,
            working_bytes: 256 * 1024 * 1024,
            index_bytes: 2 * 1024 * 1024 * 1024,
            index_record_bytes: 64 * 1024 * 1024,
        }
    }
}
