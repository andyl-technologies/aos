# System toplevel characterization goldens

These are the committed baseline snapshots for the system characterization
check (`lib/testing/system-characterization.nix`, wired as
`checks.system-characterization`). For each system variant, the snapshot pins
the deterministic, renderable outputs of `system.build.toplevel`:

```text
<variant>/
  etcDump.txt         the composefs-dump(5) text (system.build.etcDump)
  os-release          environment.etc."os-release".source, verbatim
  activate-script.sh  the substituted activate.sh.in (system.build.activateScript)
  systemd-units/*     rendered unit bodies, with job-script paths normalized to text
  systemd-units.tree  the unit directory structure (.wants/.requires + unit files)
```

Concrete store references are normalized by replacing their 32-character Nix
store hash with the literal token `<hash>`. Package and output names, versions,
subpaths, unit contents, and scripts remain exact; only the content-addressed
store identity is excluded from the fixture. `AOS_BASELIB_DIGEST`, which is an
opaque measured identity derived from the realized base-lib store path, is
similarly represented as `sha256:<base-lib-digest>`. Profile-local link names
derived from store identities are represented as `<store-identity>`. The
snapshot still pins each field's presence, location, and format without turning
a Nix store identity into a source-controlled golden value.

An unexpected diff in any of these is a **caught regression**. Job-script text
and content-address-derived identities are normalized by the comparator so the
baseline records system behavior rather than incidental store allocation.

## Regenerating the baselines

The toplevel render is Linux-only, so the baselines must be produced on a
Linux/KVM builder, not on darwin:

```sh
nix-build -A checks.system-characterization.regenerate
cp -r ./result/. tests/fixtures/system-characterization-goldens/
```

Then commit the regenerated tree as a standalone, reviewed diff. Until the
baselines are populated, the check fails (the snapshot has files the empty
golden tree lacks) — this is expected on a fresh branch before the first
regenerate, and is why the goldens are committed at the branch base.

`README.md` and `.gitkeep` are ignored by the comparator.
