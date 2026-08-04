# lib/testing/system-characterization.nix — system toplevel golden.
#
# Pure-eval characterization (no VM, no host tools) that pins the
# *deterministic, renderable* outputs of `system.build.toplevel` for a
# system variant against committed golden fixtures. This is the regression
# net the render/assemble split runs under: an unexpected
# byte diff in any snapshotted artifact fails the build.
#
# Snapshotted artifacts (per variant, under
# `tests/fixtures/system-characterization-goldens/<variant>/`):
#   - etcDump.txt        — the composefs-dump(5) text (system.build.etcDump).
#   - os-release         — environment.etc."os-release".source verbatim.
#   - activate-script.sh — the substituted activate.sh.in (system.build.activateScript).
#   - systemd-units/*    — the rendered unit bodies from
#                          system.build.systemdSystemUnits, JOB-SCRIPT NORMALIZED.
#   - systemd-units.tree — the unit directory structure (.wants/.requires install
#                          symlinks + which entries are store-backed unit files).
#
# Job-script normalization (test-plan.md review C2): the C2/F2-A change moves
# shell-snippet options (`script=`/`preStart=`/…) out of a `writeShellScriptBin`
# store path and into manifest *text* written to a generation-local path, so the
# rendered `ExecStart=`/`ExecStartPre=`/… bytes change intentionally. To keep the
# golden stable across that move, the comparator replaces any `Exec*=` value that
# points at a job-script path with the script's *text*. A path is recognized as a
# job script when it contains the marker `-unit-script-` (the current
# `writeShellScriptBin` form) or `/aos-job-scripts/` (the reserved F2 gen-local
# form). The check carries a self-test proving both forms normalize equal.
#
#   nix-build -A checks.system-characterization            # diff vs goldens
#   nix-build -A checks.system-characterization.regenerate # emit baselines to $out
#
# The baselines are produced on a Linux/KVM builder (this render needs Linux) by
# building `.regenerate` and copying its `$out` into
# `tests/fixtures/system-characterization-goldens/<variant>/`; see that directory's README.
{
  pkgs,
  lib,
  system,
  variant ? "server",
}: let
  goldensDir = ../../tests/fixtures/system-characterization-goldens + "/${variant}";

  systemdUnits = system.config.system.build.systemdSystemUnits;
  configManifest = system.config.system.build.configManifest;
  manifestSystemdPaths = builtins.map
    (path: lib.removePrefix "systemd/system/" path)
    (builtins.attrNames (lib.filterAttrs
      (path: _entry: lib.hasPrefix "systemd/system/" path)
      configManifest.etc));
  manifestSystemdPathsText = lib.concatStringsSep "\n" manifestSystemdPaths + "\n";
  etcDump = system.config.system.build.etcDump;
  activateScript = system.config.system.build.activateScript;
  osRelease = system.config.environment.etc."os-release".source;

  # The snapshot/normalize/compare logic lives in one Python program so the
  # job-script normalization and the readable unified diff are robust. Python3
  # is an AOS package (no host tools).
  snapshotPy = pkgs.writeTextFile {
    name = "system-characterization-snapshot-py";
    destination = "/snapshot.py";
    text = ''
      """System characterization: snapshot, normalize, and compare.

      Builds a normalized snapshot tree of a system toplevel's renderable
      artifacts and either writes it out (generate mode) or diffs it against a
      committed golden tree (check mode). The job-script normalization is the
      load-bearing piece: it collapses both the current `writeShellScriptBin`
      store-path form and the reserved F2 generation-local form of a
      `Exec*=`-referenced job script to the script's text, so the golden is
      stable across the C2/F2-A move.
      """

      import argparse
      import difflib
      import os
      import re
      import sys
      import tempfile

      # Markers that identify a `Exec*=` path token as a rendered job script.
      # `-unit-script-` is the current `makeJobScript`/`writeShellScriptBin`
      # store-path form; `/aos-job-scripts/` is the reserved generation-local
      # form the F2-A materializer must use (or update this marker + the golden
      # in the same reviewed diff).
      JOB_SCRIPT_MARKERS = ("-unit-script-", "/aos-job-scripts/")

      EXEC_RE = re.compile(r"^(Exec[A-Za-z]*)=(.*)$")
      # systemd Exec line special prefixes that precede the executable path.
      EXEC_PREFIX_CHARS = set("@-:+!~")

      def read_text(path):
          with open(path, "r", encoding="utf-8", errors="surrogateescape") as handle:
              return handle.read()


      def write_text(path, text):
          os.makedirs(os.path.dirname(path), exist_ok=True)
          with open(path, "w", encoding="utf-8", errors="surrogateescape") as handle:
              handle.write(text)


      def split_exec_value(value):
          """Split an Exec value into (prefix, path, args).

          `prefix` is the leading run of systemd special chars (`@-:+!~`),
          `path` is the executable token, `args` is the remainder (or None).
          """
          stripped = value.lstrip()
          prefix = ""
          rest = stripped
          while rest[:1] in EXEC_PREFIX_CHARS:
              prefix += rest[0]
              rest = rest[1:]
          token, _, remainder = rest.partition(" ")
          args = remainder if remainder.strip() != "" else None
          return prefix, token, args


      def normalize_unit_text(text):
          """Normalize a unit body so job-script paths become their text.

          Every `Exec*=` directive whose path token is a recognized job script
          and resolves to a readable file is replaced by a deterministic block
          carrying the directive name, any prefix/args, and the script body.
          All other lines pass through verbatim.
          """
          out_lines = []
          for line in text.split("\n"):
              match = EXEC_RE.match(line)
              if match is None:
                  out_lines.append(line)
                  continue
              key, value = match.group(1), match.group(2)
              prefix, token, args = split_exec_value(value)
              is_job_script = any(mark in token for mark in JOB_SCRIPT_MARKERS)
              if is_job_script and os.path.isfile(token):
                  body = read_text(token).rstrip("\n")
                  header = "%s=%s<<aos-job-script" % (key, prefix)
                  if args is not None:
                      header += " args=%s" % args
                  header += ">>"
                  out_lines.append(header)
                  out_lines.extend(body.split("\n"))
                  out_lines.append("<<aos-job-script-end>>")
              else:
                  out_lines.append(line)
          return "\n".join(out_lines)


      def snapshot_units(units_dir, out_dir):
          """Snapshot unit bodies (normalized) and the directory tree."""
          tree = []
          for dirpath, dirnames, filenames in os.walk(units_dir):
              rel_dir = os.path.relpath(dirpath, units_dir)
              for name in sorted(dirnames):
                  rel = os.path.normpath(os.path.join(rel_dir, name))
                  tree.append(("d", rel, None))
              for name in sorted(filenames):
                  full = os.path.join(dirpath, name)
                  rel = os.path.normpath(os.path.join(rel_dir, name))
                  if os.path.islink(full):
                      target = os.readlink(full)
                      if target.startswith("/nix/store/"):
                          # A store-backed unit file: snapshot its (normalized)
                          # body; omit the volatile store-path target from the
                          # tree so a body change shows up only once.
                          tree.append(("unit", rel, None))
                          body = normalize_unit_text(read_text(full))
                          write_text(os.path.join(out_dir, "systemd-units", rel), body)
                      else:
                          # An install symlink (e.g. `../foo.service`): the
                          # relative target is the stable, meaningful payload.
                          tree.append(("link", rel, target))
                  else:
                      # The P0 materializer may replace a store symlink with a
                      # regular file carrying identical bytes. Treat both
                      # representations as a semantic unit and snapshot the
                      # body, so representation-only changes compare equal
                      # while any unit-body change remains visible.
                      tree.append(("unit", rel, None))
                      body = normalize_unit_text(read_text(full))
                      write_text(os.path.join(out_dir, "systemd-units", rel), body)
          tree.sort(key=lambda entry: (entry[1], entry[0]))
          lines = []
          for kind, rel, target in tree:
              if target is None:
                  lines.append("%s\t%s" % (kind, rel))
              else:
                  lines.append("%s\t%s\t%s" % (kind, rel, target))
          write_text(os.path.join(out_dir, "systemd-units.tree"), "\n".join(lines) + "\n")


      def build_snapshot(args, out_dir):
          snapshot_units(args.units, out_dir)
          write_text(os.path.join(out_dir, "etcDump.txt"), read_text(args.etc_dump))
          write_text(os.path.join(out_dir, "os-release"), read_text(args.os_release))
          write_text(os.path.join(out_dir, "activate-script.sh"), read_text(args.activate))


      def assert_manifest_unit_paths(args):
          """Assert that the builder-side unit tree is exactly manifest-derived."""
          expected = set(read_text(args.manifest_paths).splitlines())
          actual = set()
          for dirpath, _dirnames, filenames in os.walk(args.units):
              for name in filenames:
                  actual.add(os.path.relpath(os.path.join(dirpath, name), args.units))
          if actual != expected:
              missing = sorted(expected - actual)
              extra = sorted(actual - expected)
              sys.stderr.write("systemd manifest/materializer path mismatch\n")
              sys.stderr.write("missing: %r\nextra: %r\n" % (missing, extra))
              sys.exit(1)


      def self_test():
          """Prove the comparator collapses both job-script path forms.

          Two unit bodies whose `ExecStart=` points at the same script via the
          two recognized path forms (store `-unit-script-` and gen-local
          `/aos-job-scripts/`) must normalize to identical text.
          """
          root = tempfile.mkdtemp(prefix="system-characterization-selftest-")
          body = "#!/bin/sh\nset -e\n\necho hello from the job script\n"
          store_form = os.path.join(root, "abc123-unit-script-demo-start", "bin", "demo-start")
          genlocal_form = os.path.join(root, "aos-job-scripts", "demo.service:Script.0")
          write_text(store_form, body)
          write_text(genlocal_form, body)
          unit_a = "[Service]\nType=oneshot\nExecStart=%s\n" % store_form
          unit_b = "[Service]\nType=oneshot\nExecStart=%s\n" % genlocal_form
          norm_a = normalize_unit_text(unit_a)
          norm_b = normalize_unit_text(unit_b)
          if norm_a != norm_b:
              sys.stderr.write("job-script normalization self-test FAILED\n")
              sys.stderr.write("--- store form ---\n%s\n--- gen-local form ---\n%s\n" % (norm_a, norm_b))
              sys.exit(1)
          if "<<aos-job-script" not in norm_a or "echo hello from the job script" not in norm_a:
              sys.stderr.write("job-script normalization self-test did not inline the script body\n")
              sys.exit(1)


      def compare(out_dir, goldens):
          """Diff the snapshot against the committed golden tree.

          Non-golden bookkeeping files (`README.md`, `.gitkeep`) in the golden
          dir are ignored; every other golden file must exist in the snapshot,
          and every snapshot file must match its golden byte-for-byte.
          """
          ignore = {"README.md", ".gitkeep"}
          snapshot_files = relfiles(out_dir)
          golden_files = {rel for rel in relfiles(goldens) if os.path.basename(rel) not in ignore}

          failures = []
          for rel in sorted(snapshot_files | golden_files):
              snap_path = os.path.join(out_dir, rel)
              gold_path = os.path.join(goldens, rel)
              snap_exists = rel in snapshot_files
              gold_exists = rel in golden_files
              if not gold_exists:
                  failures.append("MISSING GOLDEN: %s (snapshot has it; regenerate the baseline)" % rel)
                  continue
              if not snap_exists:
                  failures.append("STALE GOLDEN: %s (golden has it; toplevel no longer renders it)" % rel)
                  continue
              snap_text = read_text(snap_path)
              gold_text = read_text(gold_path)
              if snap_text != gold_text:
                  diff = difflib.unified_diff(
                      gold_text.splitlines(keepends=True),
                      snap_text.splitlines(keepends=True),
                      fromfile="golden/%s" % rel,
                      tofile="rendered/%s" % rel,
                  )
                  failures.append("DIFF %s:\n%s" % (rel, "".join(diff)))

          if failures:
              sys.stderr.write("==> system characterization golden MISMATCH (%d)\n\n" % len(failures))
              sys.stderr.write("\n\n".join(failures))
              sys.stderr.write("\n\nAn unexpected diff is a caught regression. An intentional change\n")
              sys.stderr.write("requires regenerating the baseline (nix-build -A\n")
              sys.stderr.write("checks.system-characterization.regenerate) in a reviewed commit.\n")
              sys.exit(1)


      def relfiles(base):
          files = set()
          for dirpath, _dirnames, filenames in os.walk(base):
              for name in filenames:
                  files.add(os.path.relpath(os.path.join(dirpath, name), base))
          return files


      def main():
          parser = argparse.ArgumentParser()
          parser.add_argument("--units", required=True)
          parser.add_argument("--etc-dump", required=True)
          parser.add_argument("--os-release", required=True)
          parser.add_argument("--activate", required=True)
          parser.add_argument("--manifest-paths", required=True)
          parser.add_argument("--out", required=True)
          parser.add_argument("--mode", required=True, choices=["check", "generate"])
          parser.add_argument("--goldens", required=True)
          args = parser.parse_args()

          self_test()
          assert_manifest_unit_paths(args)
          build_snapshot(args, args.out)
          if args.mode == "check":
              compare(args.out, args.goldens)
              print("==> system characterization: snapshot matches goldens.")
          else:
              print("==> system characterization: baseline written to $out.")


      if __name__ == "__main__":
          main()
    '';
  };

  mkRun = mode:
    pkgs.mkDerivation {
      pname = "system-characterization-${variant}-${mode}";
      version = "0";
      src = null;

      # Pull the rendered units (and thus the referenced unit-script outputs)
      # into the build closure so the normalizer can read the script bodies.
      buildDeps = [systemdUnits pkgs.python3];

      expectedManifestPaths = manifestSystemdPathsText;
      passAsFile = ["expectedManifestPaths"];

      phases = [
        {
          name = "characterize";
          script = ''
            set -eu
            snap="$PWD/snapshot"
            mkdir -p "$snap"

            ${pkgs.python3}/bin/python3 ${snapshotPy}/snapshot.py \
              --units "${systemdUnits}" \
              --etc-dump "${etcDump}" \
              --os-release "${osRelease}" \
              --activate "${activateScript}" \
              --manifest-paths "$expectedManifestPathsPath" \
              --out "$snap" \
              --mode "${mode}" \
              --goldens "${goldensDir}"

            ${
              if mode == "generate"
              then ''
                mkdir -p "$out"
                cp -r "$snap"/. "$out"/
              ''
              else ''
                mkdir -p "$out"
                echo PASS > "$out/result"
              ''
            }
          '';
        }
      ];

      meta.description = "System toplevel characterization golden (${variant}, ${mode})";
    };

  check = mkRun "check";
  regenerate = mkRun "generate";
in
  # The default attribute is the byte-diff gate; `.regenerate` emits the
  # baseline tree so the goldens can be (re)produced on a Linux builder.
  check // {inherit regenerate;}
