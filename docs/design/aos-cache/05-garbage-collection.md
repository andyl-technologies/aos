# Garbage Collection & TTLs

### 6.1 GC Root Lifecycle

```
Build completes for view "ci"
         │
         ▼
  Create symlinks:
  /var/lib/aos/gcroots/ci/bin/{hash} -> /var/lib/aos/store/{hash}-{name}   (outputs)
  /var/lib/aos/gcroots/ci/src/{hash} -> /var/lib/aos/store/{hash}-{src}    (sources)
         │
         ▼
  Write metadata:
  /var/lib/aos/meta/ci/bin/{hash}.json   (binary TTL)
  /var/lib/aos/meta/ci/src/{hash}.json   (source TTL)
  { "expires_at": now + view.ttl }
         │
         │     ┌─── aos gc (periodic) ───┐
         │     │                                │
         │     │  For each view:                │
         │     │    For each root in gcroots/:  │
         │     │      Read meta/{hash}.json     │
         │     │      If expired:               │
         │     │        Remove GC root symlink   │
         │     │        Remove meta file        │
         │     └────────────────────────────────┘
         │
         ▼
  nix-store --gc
  (Nix removes paths with no remaining GC roots)
```

### 6.2 TTL Configuration

```toml
[[views]]
name = "ci"
ttl = "7d"     # paths expire 7 days after push

[[views]]
name = "prod"
ttl = "none"   # paths never expire (manual removal only)

[[views]]
name = "dev"
ttl = "24h"    # aggressive cleanup for dev builds
```

### 6.3 GC Commands

```sh
# Remove expired GC roots across all views:
aos gc

# Remove expired GC roots for a specific view:
aos gc --view ci

# Run Nix's garbage collector after removing roots:
aos gc --collect

# Dry-run (show what would be removed):
aos gc --dry-run

# Force-remove all roots for a view (decommission):
aos gc --view dev --all
```

### 6.4 How Nix GC Integrates

The key insight: **we don't implement garbage collection**. We only manage
GC roots (symlinks). The actual garbage collection is done by `nix-store --gc`,
which Nix already implements correctly:

1. `aos gc` removes expired symlinks from `/var/lib/aos/gcroots/{view}/bin/`
   and `/var/lib/aos/gcroots/{view}/src/` (each namespace uses its own TTL)
2. `nix-store --gc` (run separately or via `--collect`) traverses all GC roots,
   computes the transitive closure of live paths, and deletes everything else

This means:
- A path pushed to both `ci` and `prod` survives as long as **either** view
  still has an active root for it
- Removing a root from one view doesn't delete the path if another view
  (or any other GC root on the system) still references it
- System profiles, development builds, and cache roots coexist naturally

### 6.5 Automated GC

For unattended operation, use a systemd timer:

```ini
[Timer]
OnCalendar=hourly
Persistent=true

[Service]
ExecStart=/usr/bin/aos gc --collect
```

Or cron: `0 * * * * aos gc --collect`

### 6.6 Size-Bounded Eviction (DAG-Aware)

When a view exceeds its `max_store_size`, TTL expiry alone isn't enough — we
need to actively evict the least-valuable closures. The Nix dependency graph
is a DAG, so eviction must respect the structure: removing a path requires
considering everything that depends on it.

#### Why Not Simple LRU

Naive per-path LRU is wrong for a DAG:
- Evicting `glibc` (shared by everything) would break the entire view
- Evicting a deep leaf dep is pointless if its parent closure is still active
- Size varies by 1000x (glibc: 30MB, a config file: 1KB) — recency alone
  doesn't capture eviction "value"

#### The Algorithm: Weighted Closure Eviction

Operate on **push roots** (`is_root: true` in metadata), not individual paths.
A push root is what the user directly built — everything else exists only as
a transitive dependency.

**Step 1**: Identify eviction candidates.

```
For each push root R in the view:
  closure(R) = transitive runtime deps of R (from Nix DB Refs table)
  unique(R)  = closure(R) - ∪{closure(R') for all other push roots R'}
  shared(R)  = closure(R) - unique(R)
```

`unique(R)` is the set of paths that ONLY this root keeps alive. Evicting R
frees exactly `Σ narSize(p) for p in unique(R)`.

**Step 2**: Score each push root.

```
effective_access(R) = max(last_accessed(p) for p in closure(R))
age(R)              = now - effective_access(R)
unique_size(R)      = Σ narSize(p) for p in unique(R)

score(R) = age(R) × unique_size(R)
```

Higher score = older and larger = evict first. This captures the intuition:
"evict the root whose closure hasn't been downloaded recently and whose
removal frees the most space."

**Why `effective_access` uses max across the closure**: if someone downloaded
*any* path in R's closure recently, R is still "in use" — even if R's own
narinfo wasn't fetched. This prevents evicting a root whose dependencies are
actively being substituted by clients.

**Step 3**: Evict greedily until under budget.

```
while view_size > max_store_size:
    R = push root with highest score
    for p in unique(R):
        rm gcroots/{view}/bin/{hash(p)}
        rm meta/{view}/bin/{hash(p)}.json
    rm gcroots/{view}/bin/{hash(R)}
    rm meta/{view}/bin/{hash(R)}.json
    view_size -= unique_size(R)
```

After removing roots, `nix-store --gc` handles the actual store path deletion.

**Complexity**: O(V + E) for a single closure computation (DFS traversal of
the Refs table). Scoring all roots: O(R × (V + E)) where R = number of push
roots. In practice, most views have <100 push roots and the Refs graph is
cached in-memory from SQLite.

#### Shared Dependencies and the "glibc Problem"

Shared dependencies (glibc, gcc-lib, bash, coreutils) appear in nearly every
closure. They are never in any root's `unique(R)` set, so they're never
evicted by the algorithm above — which is correct. They're only collected
when ALL roots that reference them are gone.

This means:
- Shared deps contribute to `view_size` but are not charged to any single root
- A view's "shared overhead" is the cumulative size of deps referenced by 2+
  roots. This is bounded and stable (it's basically the bootstrap closure).
- The `max_store_size` limit should account for this: a view with 50 push roots
  sharing a 2GB bootstrap closure needs `max_store_size ≥ 2GB + unique sizes`.

#### Example

```
View "ci" has max_store_size = 50G, currently at 65G.

Push roots (is_root=true):
  R1: foo-1.0 (last accessed 30d ago, unique deps = 8G)   → score = 30 × 8  = 240
  R2: foo-2.0 (last accessed 2d ago,  unique deps = 9G)   → score = 2  × 9  = 18
  R3: bar-3.1 (last accessed 15d ago, unique deps = 6G)   → score = 15 × 6  = 90
  R4: baz-1.2 (last accessed 20d ago, unique deps = 4G)   → score = 20 × 4  = 80
  Shared deps (glibc, gcc-lib, coreutils, ...): 3G

Eviction order: R1 (240), R3 (90), R4 (80)
  After evicting R1: 65 - 8 = 57G (still over)
  After evicting R3: 57 - 6 = 51G (still over)
  After evicting R4: 51 - 4 = 47G (under 50G — stop)

R2 (foo-2.0, recently accessed) survives.
```

#### Alternative Scoring Functions

The `age × unique_size` score is simple but effective. For views with
different access patterns, alternative scores may be useful:

```
# Frequency-weighted: penalize infrequently accessed roots more
score(R) = age(R) × unique_size(R) / log(access_count(R) + 1)

# Priority-weighted: allow config to boost certain roots
score(R) = age(R) × unique_size(R) × (1 / priority(R))
```

The scoring function is a configuration choice, not an architectural one.
Start with `age × unique_size` and tune based on real-world eviction patterns.

#### GC Command Integration

```sh
# Expire TTL roots, then evict if over budget, then collect:
aos gc --collect

# Dry-run: show what would be evicted and how much space freed:
aos gc --dry-run
# → Would evict: foo-1.0 (unique: 8G, last accessed: 30d ago, score: 240)
# → Would evict: bar-3.1 (unique: 6G, last accessed: 15d ago, score: 90)
# → Would free: 14G (65G → 51G, under 50G limit)

# Override eviction for a specific root (keep it despite score):
aos gc --pin /var/lib/aos/store/{hash}-foo-1.0
```

The two-phase GC algorithm:

```
Phase 1: TTL expiry (deterministic, O(n))
  For each root with expires_at < now: remove GC root symlink + metadata

Phase 2: Size-bounded eviction (if still over max_store_size)
  Score remaining push roots by age × unique_size
  Evict highest-score roots greedily until under budget

Phase 3: Nix GC (if --collect)
  nix-store --gc removes paths with no remaining GC roots
```

Or cron: `0 * * * * aos gc --collect`
