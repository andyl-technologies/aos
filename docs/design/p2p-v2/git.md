# Git Repositories

Git repositories are implemented as Statute key namespaces backed by the AOS
content-addressed store. Git refs (branches, tags) are Statute keys whose
values are meta object hashes. The store holds the actual content (trees,
blobs, chunks). Statute provides consensus on ref state, access control via
`_permissions`, and automatic GC pinning via `#TreeRef` values.

## Architecture

```
Statute (mutable refs)              Store (immutable content)
┌─────────────────────┐             ┌─────────────────────┐
│ /repositories/git/  │             │ objects.mdb          │
│   foo/              │             │   meta_db: commits   │
│     refs/heads/     │  ref hash   │   tree_db: trees     │
│       main ─────────┼────────────►│   blob_db: blobs     │
│       feature-x     │             │ chunk.mdb            │
│     refs/tags/      │             │   chunks             │
│       v1.0.0        │             └─────────────────────┘
│     HEAD            │
│     _permissions    │
│     _schema         │
└─────────────────────┘
```

Statute owns the mutable state (which commit each ref points to). The store
owns the immutable content (commit objects, trees, blobs, chunks). The
boundary is clean: Statute keys hold hashes, the store holds data.

## Key Structure

```
/repositories/git/{repo_path}/
    _permissions                → push/pull access control
    _schema                    → git ref schema
    HEAD                       → symbolic ref ("refs/heads/main")
    refs/
        heads/
            main               → #TreeRef (commit meta object hash)
            feature-x          → #TreeRef
        tags/
            v1.0.0             → #TreeRef (tag or commit hash)
    config                     → repository configuration
```

## Meta Objects

Git commits and tags are stored as **meta objects** in `objects.mdb/meta_db`.
A meta object is a collection of typed fields — some are string metadata,
others are object references forming a DAG.

### Commit

```
MetaObject {
    hash: blake3(serialized fields)
    fields: [
        { key: "tree",      ref: <root_tree_hash> },
        { key: "parent",    ref: <parent_commit_hash> },
        { key: "parent",    ref: <second_parent_hash> },   // merge commits
        { key: "author",    text: "Alice <alice@example.com> 1710288000 +0000" },
        { key: "committer", text: "Alice <alice@example.com> 1710288000 +0000" },
        { key: "message",   text: "Add feature X\n\nDetailed description..." },
    ]
}
```

The `tree` ref points to a TreeObject in `tree_db` (same git-compatible
merkle tree used by store objects). The `parent` refs point to other commit
MetaObjects, forming the commit history DAG.

### Tag (Annotated)

```
MetaObject {
    fields: [
        { key: "object",  ref: <commit_hash> },
        { key: "type",    text: "commit" },
        { key: "tag",     text: "v1.0.0" },
        { key: "tagger",  text: "Alice <alice@example.com> 1710288000 +0000" },
        { key: "message", text: "Release 1.0.0" },
    ]
}
```

Lightweight tags are just refs pointing directly to a commit (no MetaObject).

## Automatic GC Pinning

Git ref values in Statute are `#TreeRef` types — blake3 hashes of meta
objects. The GC scanner finds these hashes in the Statute state and pins
their entire closure:

```
Ref in Statute (commit hash)
  → meta_db: commit MetaObject
    → tree ref → tree_db: root TreeObject
      → subtree refs → tree_db: child TreeObjects
        → blob refs → blob_db: BlobRefs
          → chunk refs → chunk_db: chunks in pack files
    → parent ref → meta_db: parent commit MetaObject
      → (recurse — pins entire reachable history)
```

**Pushing a new commit:** update the ref in Statute. The new commit's closure
is automatically pinned. The old commit is still pinned if it's reachable
from the new commit (as a parent). If a branch is force-pushed (old commit
becomes unreachable), the old commit's unique objects become GC-eligible.

**Deleting a branch:** remove the ref key from Statute. Commits unique to
that branch (not reachable from any other ref) become GC-eligible.

## Schema

```cue
// /repositories/git/_schema
{
    _inherit: "default"

    [_repo=string]: {
        HEAD: string & =~"^refs/"     // symbolic ref
        refs: {
            heads: {
                [string]: #TreeRef     // branch → commit hash
            }
            tags: {
                [string]: #TreeRef     // tag → commit or tag object hash
            }
        }
        config?: {
            default_branch?: string
            description?: string
            ...
        }
    }
}
```

## Permissions

```cue
// /repositories/git/_permissions
{
    relations: {
        owner: {
            subjects: [{type: "group", ref: "/groups/repo-admins/members", through: "members"}]
        }
        pusher: {
            subjects: [
                {type: "inherit", relation: "owner"},
                {type: "group", ref: "/groups/developers/members", through: "members"},
            ]
        }
        reader: {
            subjects: [
                {type: "inherit", relation: "pusher"},
                {type: "group", ref: "/groups/all-users/members", through: "members"},
            ]
        }
    }
    rules: {
        write:  {any_of: ["pusher"]}
        read:   {any_of: ["reader"]}
        delete: {any_of: ["owner"]}
    }
}
```

Per-repo permissions can refine:

```cue
// /repositories/git/my-project/_permissions
{
    relations: {
        pusher: {
            subjects: [
                {type: "peer", id: "peer:QmAlice"},
                {type: "peer", id: "peer:QmBob"},
            ]
        }
    }
    rules: {
        write: {any_of: ["pusher"]}
    }
}
```

## Git Operations

### Clone / Fetch

1. Query Statute for `/repositories/git/{repo}/refs/heads/*` and
   `/repositories/git/{repo}/refs/tags/*` — get all ref → commit hash mappings.
2. For each commit hash, fetch the MetaObject from the store (via resolve +
   chunk protocols). The commit's tree ref gives the root tree.
3. Fetch the tree/blob content via the normal store transfer flow (resolve +
   chunk protocols, parallel chunk download).
4. The client now has the full repo content locally.

### Push

1. Client uploads new tree/blob objects to the store (via upload protocol).
2. Client creates commit MetaObject(s) referencing the tree + parent commits.
3. Client uploads the commit MetaObject(s) to the store.
4. Client writes the new commit hash to the ref in Statute:
   - Write `/repositories/git/{repo}/refs/heads/main` = new_commit_hash
   - Statute validates: UCAN (push permission), schema (#TreeRef format)
   - Statute consensus commits the ref update.
5. GC pins the new commit's closure. Old unreachable commits become eligible.

### Branch / Tag Operations

All are Statute writes:
- Create branch: write new key at `/repositories/git/{repo}/refs/heads/{name}`
- Delete branch: delete the key
- Create tag: write key at `/repositories/git/{repo}/refs/tags/{name}`
- Force push: overwrite the ref value (Statute history records who did it)

## Protocol

```protobuf
// Meta object: a collection of typed fields forming a DAG.
// Stored in objects.mdb/meta_db. Used for git commits, tags,
// and other structured metadata that references store objects.
// The hash is blake3 of the serialized fields.
message MetaObject {
    bytes hash = 1;                    // blake3 of the serialized meta object
    repeated MetaField fields = 2;     // ordered fields
}

// A single field in a meta object. Values are either string metadata
// (author, message, timestamp) or object references (forming the DAG).
message MetaField {
    string key = 1;                    // field name (e.g., "tree", "parent", "author")
    oneof value {
        bytes ref = 2;                 // blake3 hash → tree/blob/meta object (DAG edge)
        string text = 3;              // string metadata
        uint64 integer = 4;           // numeric metadata
    }
}
```

## Relationship to Other Docs

- [statute.md](statute.md) -- Statute KV store where refs are stored. Auto-pinning
  via #TreeRef values in the state.
- [git-store.md](git-store.md) -- git-compatible merkle tree model for trees/blobs.
- [storage.md](storage.md) -- objects.mdb meta_db for commit/tag storage.
- [store.md](store.md) -- store transfer protocol for cloning/fetching content.
- [store-upload.md](store-upload.md) -- upload protocol for pushing content.
- [gc.md](gc.md) -- GC closure walker follows meta object refs.
- [system.md](system.md) -- git as a system built on the four building blocks.
