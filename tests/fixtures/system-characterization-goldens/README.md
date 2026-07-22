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

An unexpected diff in any of these is a **caught regression** (the barrier
pattern). The single intentional change permitted during the P0 render/assemble
refactor is the documented job-script-text normalization, which the comparator
already absorbs (see the C2 note in `docs/rfcs/0011-on-host-config-eval/test-plan.md`).

## Regenerating the baselines

The toplevel render is Linux-only, so the baselines must be produced on a
Linux/KVM builder, not on darwin:

```sh
nix-build -A checks.system-characterization.regenerate
cp -r ./result/. tests/fixtures/system-characterization-goldens/server/
```

Then commit the regenerated tree as a standalone, reviewed diff. Until the
baselines are populated, the check fails (the snapshot has files the empty
golden tree lacks) — this is expected on a fresh branch before the first
regenerate, and is why the goldens are committed at the branch base.

`README.md` and `.gitkeep` are ignored by the comparator.
